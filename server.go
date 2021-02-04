package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	UserId uint `gorm:"primary_key" json: "user_id"`
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
	Email string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Database struct {
	DB *gorm.DB
}

type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func main() {
	e := echo.New()

	  // Middleware
  e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, world!")
	})
	
	e.GET("/hash", func(c echo.Context) error {
		hash, _ := HashPassword("123456")

		return c.String(http.StatusOK, hash)
	})

	d := Database{}
	d.Initialize()


	e.POST("/login", d.Login)


	r := e.Group("/api")

	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("secret"),
	}

	r.Use(middleware.JWTWithConfig(config))

	r.GET("/users/:id", d.GetInfo)
	r.GET("/users", d.GetAll)
	r.POST("/users", d.Create)

	r.PUT("/users/:id", d.Update)
	r.DELETE("/users/:id", d.Delete)

	r.GET("/test-jwt", TestJwt)

	e.Logger.Fatal(e.Start(":8080"))
}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func (d *Database) Initialize() {
	db, err := gorm.Open("mysql", "root:789124@tcp(127.0.0.1:3306)/test?charset=utf8&parseTime=True");
	if err != nil {
		log.Fatal(err)
	}

	d.DB = db
}

func (d *Database) GetAll(c echo.Context) error {
	users := []User{}
	if err := d.DB.Find(&users).Error; err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, users)
}

func (d *Database) GetInfo(c echo.Context) error {
	id := c.Param("id")

	user := User{}
	if err := d.DB.First(&user, id).Error; err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, user)
}

func (d *Database) Create(c echo.Context) error {

	firstName := c.FormValue("firstName")
	lastName := c.FormValue("lastName")
	email := c.FormValue("email")
	password := c.FormValue("password")
	username := c.FormValue("username")

	hash, _ := HashPassword(password)

	result := d.DB.Create(&User{FirstName: firstName, LastName: lastName, Email: email, Password: hash, Username: username})
	
	if result.Error != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, result.Value)
}

func (d *Database) Update(c echo.Context) error {

	id := c.Param("id")
	user := User{}

	firstName := c.FormValue("firstName")
	lastName := c.FormValue("lastName")
	email := c.FormValue("email")

	if  err := d.DB.Find(&user, id).Error; err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	user.FirstName = firstName
	user.LastName = lastName
	user.Email = email 

	if err := d.DB.Save(&user).Error; err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, user)
}

func (d *Database) Delete(c echo.Context) error {
	id := c.Param("id")

	if err := d.DB.Delete(&User{}, id).Error; err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	return c.NoContent(http.StatusNoContent)
}

func TestJwt(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Name

	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func (d *Database) Login(c echo.Context) error {
	user := User{}

	username := c.FormValue("username")
	password :=c.FormValue("password")

	result := d.DB.Where(&User{Username: username}).Find(&user)

	if result.Error != nil {
		return c.NoContent(http.StatusNotFound)
	}

	if result.RowsAffected == 0 {
		return c.NoContent(http.StatusUnauthorized)
	}
	hash := user.Password
	match := CheckPasswordHash(password, hash)

	if !match {
		return c.NoContent(http.StatusUnauthorized)
	}
	// Create token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = "Satit Rianpit"
	claims["admin"] = true
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{
		"token": t,
	})

}