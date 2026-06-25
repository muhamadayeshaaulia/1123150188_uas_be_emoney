package models

import "gorm.io/gorm"

type Account struct {
	gorm.Model
	UserID  uint    `gorm:"uniqueIndex;not null" json:"user_id"`
	Balance float64 `gorm:"default:0;type:decimal(15,2)" json:"balance"`
	User    User    `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

type Transaction struct {
	gorm.Model
	AccountID     uint    `gorm:"not null;index" json:"account_id"`
	Amount        float64 `gorm:"type:decimal(15,2)" json:"amount"`
	TotalAmount   float64 `gorm:"type:decimal(15,2)" json:"total_amount"`
	InvoiceID     string  `gorm:"type:varchar(50);index" json:"invoice_id"`
	Status        string  `gorm:"type:varchar(20);default:'SUCCESS'" json:"status"`
	Type          string  `gorm:"type:varchar(10)" json:"type"` // "debit" | "credit"
	Description   string  `gorm:"type:varchar(255)" json:"description"`
	BalanceBefore float64 `gorm:"type:decimal(15,2)" json:"balance_before"`
	BalanceAfter  float64 `gorm:"type:decimal(15,2)" json:"balance_after"`
	Account       Account `gorm:"foreignKey:AccountID" json:"-"`
}
