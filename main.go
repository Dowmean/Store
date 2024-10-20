package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB
var err error
var jwtKey = []byte("my_secret_key")

type Product struct {
	ID       uint    `gorm:"primaryKey"`
	Name     string  `gorm:"size:255;not null"`
	Type     string  `gorm:"size:255;not null"`
	Quantity int     `gorm:"not null"`
	Price    float64 `gorm:"not null"`
}

type Order struct {
	ID        uint    `gorm:"primaryKey"`
	ProductID uint    `gorm:"not null"`
	UserID    uint    `gorm:"not null"`
	Quantity  int     `gorm:"not null"`
	Price     float64 `gorm:"not null"`
}

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"size:255;not null;unique"`
	Password string `gorm:"size:255;not null"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func initDB() {
	dsn := "store:1234@tcp(127.0.0.1:3306)/exercise_store?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	err = db.AutoMigrate(&User{}, &Product{}, &Order{})
	if err != nil {
		log.Fatalf("Error with AutoMigrate: %v", err)
	}

	log.Println("Database connected and AutoMigrated successfully!")
}

func signup(c *gin.Context) {
	var creds Credentials
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	user := User{Username: creds.Username, Password: string(hashedPassword)}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful!"})
}

func login(c *gin.Context) {
	var creds Credentials
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	if err := db.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	c.SetCookie("token", tokenString, 300, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful!"})
}

func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func getProducts(c *gin.Context) {
	var products []struct {
		Name  string  `json:"name"`
		Price float64 `json:"price"`
	}
	db.Model(&Product{}).Select("name, price").Find(&products)
	c.JSON(http.StatusOK, products)
}

func getProductByID(c *gin.Context) {
	productID := c.Param("id")
	var product Product

	if err := db.Where("id = ?", productID).First(&product).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	c.JSON(http.StatusOK, product)
}

func createOrder(c *gin.Context) {
	var order Order
	if err := c.ShouldBindJSON(&order); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var product Product
	if err := db.Where("id = ?", order.ProductID).First(&product).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product not found"})
		return
	}

	totalPrice := product.Price * float64(order.Quantity)

	order.UserID = 1
	order.Price = totalPrice

	if err := db.Create(&order).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create order"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Order created successfully!", "total_price": totalPrice})
}

func getOrders(c *gin.Context) {
	userID := 1
	var orders []Order
	db.Where("user_id = ?", userID).Find(&orders)
	c.JSON(http.StatusOK, orders)
}

func main() {
	initDB()

	r := gin.Default()

	// Public routes
	r.POST("/signup", signup)
	r.POST("/login", login)
	r.GET("/products", getProducts)         
	r.GET("/products/:id", getProductByID) 

	// Protected routes
	protected := r.Group("/orders")
	protected.Use(jwtMiddleware())
	protected.POST("", createOrder)
	protected.GET("", getOrders)

	r.Run(":8080")
}
