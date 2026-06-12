package handlers

import (
	"context"
	"net/http"
	"time"

	"emoney-2fa/config"
	"emoney-2fa/models"
	"emoney-2fa/services"

	firebase "firebase.google.com/go/v4"
	fbauth "firebase.google.com/go/v4/auth"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db          *gorm.DB
	firebaseApp *firebase.App
	jwtSvc      *services.JWTService
	otpSvc      *services.OTPService
	cfg         *config.Config
}

func NewAuthHandler(db *gorm.DB, firebaseApp *firebase.App, jwtSvc *services.JWTService, otpSvc *services.OTPService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{db: db, firebaseApp: firebaseApp, jwtSvc: jwtSvc, otpSvc: otpSvc, cfg: cfg}
}

type VerifyTokenRequest struct {
	FirebaseToken string `json:"firebase_token" binding:"required"`
}

type UpdateFCMTokenRequest struct {
	FCMToken string `json:"fcm_token" binding:"required"`
}

func (h *AuthHandler) VerifyToken(c *gin.Context) {
	var req VerifyTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "firebase_token diperlukan",
		})
		return
	}

	ctx := context.Background()
	authClient, err := h.firebaseApp.Auth(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Firebase auth error",
		})
		return
	}

	token, err := authClient.VerifyIDToken(ctx, req.FirebaseToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success":    false,
			"message":    "Token tidak valid atau kadaluarsa",
			"error_code": "INVALID_FIREBASE_TOKEN",
		})
		return
	}

	emailVerified, _ := token.Claims["email_verified"].(bool)
	email, _ := token.Claims["email"].(string)
	name, _ := token.Claims["name"].(string)

	var user models.User
	result := h.db.WithContext(ctx).Where("firebase_uid = ?", token.UID).First(&user)

	if result.Error == gorm.ErrRecordNotFound {
		user = models.User{
			FirebaseUID:   token.UID,
			Email:         email,
			Name:          name,
			Role:          "user",
			EmailVerified: emailVerified,
		}
		if err := h.db.WithContext(ctx).Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Gagal membuat user",
			})
			return
		}

		account := models.Account{UserID: user.ID, Balance: 0}
		h.db.WithContext(ctx).Create(&account)
	} else if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Database error",
		})
		return
	} else {
		h.db.WithContext(ctx).Model(&user).Updates(map[string]interface{}{
			"email":          email,
			"name":           name,
			"email_verified": emailVerified,
		})
	}

	jwtToken, err := h.jwtSvc.GenerateToken(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Gagal membuat token",
		})
		return
	}

	userResponse := models.UserResponse{
		ID:            user.ID,
		FirebaseUID:   user.FirebaseUID,
		Email:         user.Email,
		Name:          user.Name,
		Role:          user.Role,
		EmailVerified: user.EmailVerified,
		TOTPEnabled:   user.TOTPEnabled,
		CreatedAt:     user.CreatedAt.Format(time.RFC3339),
	}

	if !emailVerified {
		// Email belum diverifikasi di Firebase → kirim email verifikasi resmi
		// dari Firebase (link verify-email) lewat Identity Toolkit REST API.
		if err := services.SendEmailVerificationLink(h.cfg.FirebaseAPIKey, req.FirebaseToken); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Gagal mengirim email verifikasi: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusForbidden, gin.H{
			"success":    false,
			"message":    "Email belum diverifikasi. Tautan verifikasi telah dikirim ke email Anda.",
			"error_code": "EMAIL_NOT_VERIFIED",
			"data": gin.H{
				"access_token": jwtToken,
				"token_type":   "Bearer",
				"expires_in":   86400,
				"user":         userResponse,
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Login berhasil",
		"data": gin.H{
			"access_token": jwtToken,
			"token_type":   "Bearer",
			"expires_in":   86400,
			"user":         userResponse,
		},
	})
}

func (h *AuthHandler) UpdateFCMToken(c *gin.Context) {
	userID := c.GetUint("user_id")

	var req UpdateFCMTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "fcm_token diperlukan",
		})
		return
	}

	if err := h.db.Model(&models.User{}).Where("id = ?", userID).
		Update("fcm_token", req.FCMToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Gagal update FCM token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "FCM token berhasil diupdate",
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID := c.GetUint("user_id")

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "User tidak ditemukan",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": models.UserResponse{
			ID:            user.ID,
			FirebaseUID:   user.FirebaseUID,
			Email:         user.Email,
			Name:          user.Name,
			Role:          user.Role,
			EmailVerified: user.EmailVerified,
			TOTPEnabled:   user.TOTPEnabled,
			CreatedAt:     user.CreatedAt.Format(time.RFC3339),
		},
	})
}

// POST /v1/auth/register — public, no email_verified required.
// Creates the user in DB, issues JWT, and sends an OTP to the user's email.
func (h *AuthHandler) RegisterWithOTP(c *gin.Context) {
	var req VerifyTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "firebase_token diperlukan",
		})
		return
	}

	ctx := context.Background()
	authClient, err := h.firebaseApp.Auth(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Firebase auth error"})
		return
	}

	token, err := authClient.VerifyIDToken(ctx, req.FirebaseToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success":    false,
			"message":    "Token Firebase tidak valid atau kadaluarsa",
			"error_code": "INVALID_FIREBASE_TOKEN",
		})
		return
	}

	email, _ := token.Claims["email"].(string)
	name, _ := token.Claims["name"].(string)

	var user models.User
	result := h.db.WithContext(ctx).Where("firebase_uid = ?", token.UID).First(&user)
	if result.Error == gorm.ErrRecordNotFound {
		user = models.User{
			FirebaseUID:   token.UID,
			Email:         email,
			Name:          name,
			Role:          "user",
			EmailVerified: false,
		}
		if err := h.db.WithContext(ctx).Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Gagal membuat user"})
			return
		}
		account := models.Account{UserID: user.ID, Balance: 0}
		h.db.WithContext(ctx).Create(&account)
	} else if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Database error"})
		return
	}

	jwtToken, err := h.jwtSvc.GenerateToken(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Gagal membuat token"})
		return
	}

	if err := h.otpSvc.SendEmailOTP(ctx, &user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Gagal mengirim OTP ke email: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Registrasi berhasil. Cek email untuk kode OTP.",
		"data": gin.H{
			"access_token": jwtToken,
			"token_type":   "Bearer",
			"expires_in":   86400,
			"user": models.UserResponse{
				ID:            user.ID,
				FirebaseUID:   user.FirebaseUID,
				Email:         user.Email,
				Name:          user.Name,
				Role:          user.Role,
				EmailVerified: user.EmailVerified,
				TOTPEnabled:   user.TOTPEnabled,
				CreatedAt:     user.CreatedAt.Format(time.RFC3339),
			},
		},
	})
}

// POST /v1/auth/verify-email-otp — JWT required.
// Verifies the OTP sent to email and marks the user's email as verified in DB.
type VerifyEmailOTPRequest struct {
	Code string `json:"code" binding:"required"`
}

func (h *AuthHandler) VerifyEmailOTP(c *gin.Context) {
	userID := c.GetUint("user_id")

	var req VerifyEmailOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "code diperlukan"})
		return
	}

	ctx := c.Request.Context()

	valid := h.otpSvc.VerifyOTPRedis(ctx, userID, req.Code, models.OTPTypeEmail)
	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success":    false,
			"message":    "Kode OTP tidak valid atau sudah kadaluarsa",
			"error_code": "INVALID_OTP",
		})
		return
	}

	var user models.User
	if err := h.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "User tidak ditemukan"})
		return
	}

	// Sinkronkan status verifikasi ke Firebase, supaya ID Token Firebase
	// berikutnya membawa email_verified = true (dipakai oleh /v1/auth/verify-token).
	authClient, err := h.firebaseApp.Auth(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Firebase auth error"})
		return
	}
	if _, err := authClient.UpdateUser(ctx, user.FirebaseUID, (&fbauth.UserToUpdate{}).EmailVerified(true)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Gagal update status verifikasi email di Firebase: " + err.Error(),
		})
		return
	}

	if err := h.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("email_verified", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Gagal update status email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Email berhasil diverifikasi",
	})
}
