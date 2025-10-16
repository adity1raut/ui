package routes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwtconfig "github.com/kubestellar/ui/backend/jwt"
	"github.com/kubestellar/ui/backend/middleware"
	"github.com/kubestellar/ui/backend/models"
	database "github.com/kubestellar/ui/backend/postgresql/Database"
	"github.com/kubestellar/ui/backend/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHub OAuth configuration
var githubOAuthConfig *oauth2.Config

// Initialize GitHub OAuth config
func InitGitHubOAuth() {
	githubOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GITHUB_REDIRECT_URL"), // e.g., "http://localhost:4000/auth/github/callback"
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
}

// SetupRoutes initializes all routes - THIS IS THE MISSING FUNCTION!
func setupdebug(router *gin.Engine) {
	// Temporary debug endpoint - REMOVE IN PRODUCTION
	router.GET("/debug/admin", func(c *gin.Context) {
		// Check if admin user exists
		query := "SELECT id, username, password, is_admin FROM users WHERE username = $1"
		var id int
		var username, password string
		var isAdmin bool

		err := database.DB.QueryRow(query, "admin").Scan(&id, &username, &password, &isAdmin)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Admin user not found", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":            id,
			"username":      username,
			"password_hash": password,
			"is_admin":      isAdmin,
		})
	})

	// Debug endpoint to check all users in database
	router.GET("/debug/users", func(c *gin.Context) {
		query := "SELECT id, username, password, is_admin FROM users"
		rows, err := database.DB.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query users", "details": err.Error()})
			return
		}
		defer rows.Close()

		var users []gin.H
		for rows.Next() {
			var id int
			var username, password string
			var isAdmin bool

			err := rows.Scan(&id, &username, &password, &isAdmin)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan user", "details": err.Error()})
				return
			}

			users = append(users, gin.H{
				"id":            id,
				"username":      username,
				"password_hash": password,
				"is_admin":      isAdmin,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"users": users,
			"total": len(users),
		})
	})

	// Debug endpoint to check user permissions table
	router.GET("/debug/permissions", func(c *gin.Context) {
		query := "SELECT user_id, component, permission FROM user_permissions"
		rows, err := database.DB.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query permissions", "details": err.Error()})
			return
		}
		defer rows.Close()

		var permissions []gin.H
		for rows.Next() {
			var userID int
			var component, permission string

			err := rows.Scan(&userID, &component, &permission)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan permission", "details": err.Error()})
				return
			}

			permissions = append(permissions, gin.H{
				"user_id":    userID,
				"component":  component,
				"permission": permission,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"permissions": permissions,
			"total":       len(permissions),
		})
	})
}

// setupAuthRoutes initializes authentication-related routes
func setupAuthRoutes(router *gin.Engine) {

	setupdebug(router) // Add debug routes for testing

	// Initialize GitHub OAuth
	InitGitHubOAuth()

	// Public routes (no authentication required)
	router.POST("/login", LoginHandler)
	router.POST("/api/refresh", RefreshTokenHandler)

	// GitHub OAuth routes
	router.GET("/auth/github", GitHubLoginHandler)
	router.GET("/auth/github/callback", GitHubCallbackHandler)

	// API group - ALL endpoints require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthenticateMiddleware()) // Apply authentication to ALL API routes
	{
		// Basic authenticated user endpoints
		api.GET("/me", CurrentUserHandler)
		api.PUT("/me/password", ChangePasswordHandler)

		// Component-based permission routes - ALL require authentication FIRST
		setupComponentRoutes(api)

		// Admin-only endpoints - require authentication AND admin role
		admin := api.Group("/admin")
		admin.Use(middleware.RequireAdmin())
		{
			admin.GET("/users", ListUsersHandler)
			admin.POST("/users", CreateUserHandler)
			admin.PUT("/users/:username", UpdateUserHandler)
			admin.DELETE("/users/:username", DeleteUserHandler)
			admin.GET("/users/deleted", ListDeletedUsersHandler)
			admin.GET("/users/:username/permissions", GetUserPermissionsHandler)
			admin.PUT("/users/:username/permissions", SetUserPermissionsHandler)
		}
	}
}

// setupComponentRoutes sets up routes for different components with permissions
func setupComponentRoutes(protected *gin.RouterGroup) {
	// Resources component routes - ALL require authentication + specific permissions
	resources := protected.Group("/resources")
	{
		// Read access - must be authenticated AND have read permission for resources
		resources.GET("/", middleware.RequirePermission("resources", "read"), GetResourcesHandler)
		resources.GET("/:id", middleware.RequirePermission("resources", "read"), GetResourceHandler)

		// Write access - must be authenticated AND have write permission for resources
		resources.POST("/", middleware.RequirePermission("resources", "write"), CreateResourceHandler)
		resources.PUT("/:id", middleware.RequirePermission("resources", "write"), UpdateResourceHandler)
		resources.DELETE("/:id", middleware.RequirePermission("resources", "write"), DeleteResourceHandler)
	}

	// System component routes - ALL require authentication + specific permissions
	system := protected.Group("/system")
	{
		// Read access - must be authenticated AND have read permission for system
		system.GET("/status", middleware.RequirePermission("system", "read"), GetSystemStatusHandler)
		system.GET("/config", middleware.RequirePermission("system", "read"), GetSystemConfigHandler)

		// Write access - must be authenticated AND have write permission for system
		system.PUT("/config", middleware.RequirePermission("system", "write"), UpdateSystemConfigHandler)
		system.POST("/restart", middleware.RequirePermission("system", "write"), RestartSystemHandler)
	}

	// Dashboard component routes - ALL require authentication + specific permissions
	dashboard := protected.Group("/dashboard")
	{
		// Read access - must be authenticated AND have read permission for dashboard
		dashboard.GET("/stats", middleware.RequirePermission("dashboard", "read"), GetDashboardStatsHandler)
		dashboard.GET("/charts", middleware.RequirePermission("dashboard", "read"), GetDashboardChartsHandler)

		// Write access - must be authenticated AND have write permission for dashboard
		dashboard.POST("/widgets", middleware.RequirePermission("dashboard", "write"), CreateDashboardWidgetHandler)
		dashboard.PUT("/widgets/:id", middleware.RequirePermission("dashboard", "write"), UpdateDashboardWidgetHandler)
		dashboard.DELETE("/widgets/:id", middleware.RequirePermission("dashboard", "write"), DeleteDashboardWidgetHandler)
	}
}

// ===================================
// Authentication Handlers
// ===================================

// LoginHandler verifies user credentials and issues JWT
func LoginHandler(c *gin.Context) {
	var loginData struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate input
	loginData.Username = strings.TrimSpace(loginData.Username)
	loginData.Password = strings.TrimSpace(loginData.Password)

	if loginData.Username == "" || loginData.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	// TEMPORARY: Try direct database authentication for debugging
	if loginData.Username == "admin" && loginData.Password == "admin" {
		// Get user directly from database
		query := "SELECT id, username, password, is_admin FROM users WHERE username = $1"
		var id int
		var username, dbPassword string
		var isAdmin bool

		err := database.DB.QueryRow(query, "admin").Scan(&id, &username, &dbPassword, &isAdmin)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in database"})
			return
		}

		// Check if password matches using bcrypt
		if models.CheckPasswordHash(loginData.Password, dbPassword) {
			// Create a simple user object for response
			user := struct {
				ID          int               `json:"id"`
				Username    string            `json:"username"`
				IsAdmin     bool              `json:"is_admin"`
				Permissions map[string]string `json:"permissions"`
			}{
				ID:       id,
				Username: username,
				IsAdmin:  isAdmin,
				Permissions: map[string]string{
					"users":     "write",
					"resources": "write",
					"system":    "write",
					"dashboard": "write",
				},
			}

			accessToken, refreshToken, err := issueTokens(user.ID, user.Username, user.IsAdmin, user.Permissions)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
				return
			}

			sendLoginResponse(c, accessToken, refreshToken, user.Username, user.IsAdmin, user.Permissions)
			return
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Password mismatch",
				"debug": "Bcrypt verification failed for stored hash: " + dbPassword,
			})
			return
		}
	}

	// Get user from database
	query := "SELECT id, username, password, is_admin FROM users WHERE username = $1"
	var id int
	var username, dbPassword string
	var isAdmin bool

	err := database.DB.QueryRow(query, loginData.Username).Scan(&id, &username, &dbPassword, &isAdmin)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Verify password using bcrypt
	if !models.CheckPasswordHash(loginData.Password, dbPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Get user permissions
	permissionsQuery := "SELECT component, permission FROM user_permissions WHERE user_id = $1"
	permRows, err := database.DB.Query(permissionsQuery, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user permissions"})
		return
	}
	defer permRows.Close()

	permissions := make(map[string]string)
	for permRows.Next() {
		var component, permission string
		err := permRows.Scan(&component, &permission)
		if err != nil {
			continue
		}
		permissions[component] = permission
	}

	// If admin user has no specific permissions, give them all permissions
	if isAdmin && len(permissions) == 0 {
		permissions = map[string]string{
			"users":     "write",
			"resources": "write",
			"system":    "write",
			"dashboard": "write",
		}
	}

	accessToken, refreshToken, err := issueTokens(id, username, isAdmin, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	sendLoginResponse(c, accessToken, refreshToken, username, isAdmin, permissions)
}

func issueTokens(userID int, username string, isAdmin bool, permissions map[string]string) (string, string, error) {
	accessToken, err := utils.GenerateToken(username, isAdmin, permissions, userID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := utils.GenerateRefreshToken(username, userID)
	if err != nil {
		return "", "", err
	}

	expiryDuration := jwtconfig.GetRefreshTokenExpiration()
	var expiryPtr *time.Time
	if expiryDuration > 0 {
		expiresAt := time.Now().Add(expiryDuration)
		expiryPtr = &expiresAt
	}

	if err := models.ReplaceRefreshToken(userID, refreshToken, expiryPtr); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func sendLoginResponse(c *gin.Context, accessToken, refreshToken, username string, isAdmin bool, permissions map[string]string) {
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"token":        accessToken,
		"refreshToken": refreshToken,
		"user": gin.H{
			"username":    username,
			"is_admin":    isAdmin,
			"permissions": permissions,
		},
	})
}

// RefreshTokenHandler exchanges a valid refresh token for a new access token
func RefreshTokenHandler(c *gin.Context) {
	var payload struct {
		RefreshToken string `json:"refreshToken" binding:"required"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	payload.RefreshToken = strings.TrimSpace(payload.RefreshToken)
	if payload.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token is required"})
		return
	}

	claims, err := utils.ValidateRefreshToken(payload.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	storedToken, err := models.GetRefreshTokenByToken(payload.RefreshToken)
	if err != nil {
		if errors.Is(err, models.ErrRefreshTokenNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token not recognized"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify refresh token"})
		return
	}

	if storedToken.UserID != claims.UserID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token does not match user"})
		return
	}

	if storedToken.ExpiresAt.Valid && storedToken.ExpiresAt.Time.Before(time.Now()) {
		_ = models.DeleteRefreshTokenByID(storedToken.ID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token expired"})
		return
	}

	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	accessToken, refreshToken, err := issueTokens(user.ID, user.Username, user.IsAdmin, user.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":        accessToken,
		"refreshToken": refreshToken,
	})
}

// RegisterHandler creates a new user (removed - no public registration)
// Public registration has been removed for security. Only admins can create users.

// CurrentUserHandler returns the current user's information
func CurrentUserHandler(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	isAdmin, _ := c.Get("is_admin")
	permissions, _ := c.Get("permissions")

	c.JSON(http.StatusOK, gin.H{
		"username":    username,
		"is_admin":    isAdmin,
		"permissions": permissions,
	})
}

// ChangePasswordHandler allows users to change their own password
func ChangePasswordHandler(c *gin.Context) {
	var passwordData struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&passwordData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	username, _ := c.Get("username")

	// Verify current password
	user, err := models.AuthenticateUser(username.(string), passwordData.CurrentPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		return
	}

	// Update password
	err = models.UpdateUserPassword(user.ID, passwordData.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// ===================================
// Admin User Management Handlers
// ===================================

// ListUsersHandler returns a list of all users (admin only)
func ListUsersHandler(c *gin.Context) {
	// First, let's try a direct database query to check if users exist
	query := "SELECT COUNT(*) FROM users"
	var count int
	err := database.DB.QueryRow(query).Scan(&count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to check user table",
			"details": err.Error(),
		})
		return
	}

	if count == 0 {
		c.JSON(http.StatusOK, gin.H{
			"users":   []gin.H{},
			"message": "No users found in database",
		})
		return
	}

	// Try to get users directly from database
	usersQuery := `
		SELECT u.id, u.username, u.is_admin, u.created_at, u.updated_at,
		       COALESCE(up.component, '') as component, 
		       COALESCE(up.permission, '') as permission
		FROM users u
		LEFT JOIN user_permissions up ON u.id = up.user_id
		ORDER BY u.id, up.component
	`

	rows, err := database.DB.Query(usersQuery)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to query users",
			"details": err.Error(),
		})
		return
	}
	defer rows.Close()

	userMap := make(map[int]gin.H)

	for rows.Next() {
		var id int
		var username string
		var isAdmin bool
		var createdAt, updatedAt string
		var component, permission string

		err := rows.Scan(&id, &username, &isAdmin, &createdAt, &updatedAt, &component, &permission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to scan user row",
				"details": err.Error(),
			})
			return
		}

		// Initialize user if not exists
		if _, exists := userMap[id]; !exists {
			userMap[id] = gin.H{
				"id":          id,
				"username":    username,
				"is_admin":    isAdmin,
				"created_at":  createdAt,
				"updated_at":  updatedAt,
				"permissions": make(map[string]string),
			}
		}

		// Add permission if it exists
		if component != "" && permission != "" {
			permissions := userMap[id]["permissions"].(map[string]string)
			permissions[component] = permission
		}
	}

	// Convert map to slice
	var users []gin.H
	for _, user := range userMap {
		users = append(users, user)
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": len(users),
	})
}

// CreateUserHandler creates a new user (admin only)
func CreateUserHandler(c *gin.Context) {
	var userData struct {
		Username    string            `json:"username" binding:"required"`
		Password    string            `json:"password" binding:"required"`
		IsAdmin     bool              `json:"is_admin"`
		Permissions map[string]string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Validate username
	if err := utils.ValidateUsername(userData.Username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid username",
			"details": err.Error(),
		})
		return
	}

	// Validate password
	if err := utils.ValidatePassword(userData.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid password",
			"details": err.Error(),
		})
		return
	}

	// Create user
	user, err := models.CreateUser(userData.Username, userData.Password, userData.IsAdmin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create user",
			"details": err.Error(),
		})
		return
	}

	// Set permissions if provided
	if userData.Permissions != nil {
		var permSlice []models.Permission
		for component, permission := range userData.Permissions {
			permSlice = append(permSlice, models.Permission{
				Component:  component,
				Permission: permission,
			})
		}

		err = models.SetUserPermissions(user.ID, permSlice)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "User created but failed to set permissions",
				"details": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":  "User created successfully",
		"username": userData.Username,
	})
}

func UpdateUserHandler(c *gin.Context) {
	username := c.Param("username")

	// Validate URL parameter username
	if err := utils.ValidateUsername(username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid username in URL",
			"details": err.Error(),
		})
		return
	}

	var userData struct {
		Username    string            `json:"username"`
		Password    string            `json:"password"`
		IsAdmin     bool              `json:"is_admin"`
		Permissions map[string]string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Validate new username if provided
	if userData.Username != "" {
		if err := utils.ValidateUsername(userData.Username); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid new username",
				"details": err.Error(),
			})
			return
		}
	}

	// Validate password if provided
	if userData.Password != "" {
		if err := utils.ValidatePassword(userData.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid password",
				"details": err.Error(),
			})
			return
		}
	}

	// Get existing user
	user, err := models.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Update username if provided and different
	if userData.Username != "" && userData.Username != username {
		err = models.UpdateUserUsername(user.ID, userData.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to update username",
				"details": err.Error(),
			})
			return
		}
		// Update the username for subsequent operations
		username = userData.Username
	}

	// Update password if provided
	if userData.Password != "" {
		err = models.UpdateUserPassword(user.ID, userData.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to update password",
				"details": err.Error(),
			})
			return
		}
	}

	// Update admin status if provided
	if userData.IsAdmin != user.IsAdmin {
		query := `UPDATE users SET is_admin = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`
		_, err = database.DB.Exec(query, userData.IsAdmin, user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to update admin status",
				"details": err.Error(),
			})
			return
		}
	}

	// Update permissions if provided
	if userData.Permissions != nil {
		var permSlice []models.Permission
		for component, permission := range userData.Permissions {
			permSlice = append(permSlice, models.Permission{
				Component:  component,
				Permission: permission,
			})
		}

		err = models.SetUserPermissions(user.ID, permSlice)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to update permissions",
				"details": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "User updated successfully",
		"username": username,
	})
}

func DeleteUserHandler(c *gin.Context) {
	username := c.Param("username")

	// Validate URL parameter username
	if err := utils.ValidateUsername(username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid username in URL",
			"details": err.Error(),
		})
		return
	}

	// Prevent deleting the last admin user
	if username == "admin" {
		users, err := models.ListAllUsers()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to check admin users",
				"details": err.Error(),
			})
			return
		}
		adminCount := 0
		for _, user := range users {
			if user.IsAdmin {
				adminCount++
			}
		}
		if adminCount <= 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete the last admin user"})
			return
		}
	}

	err := models.DeleteUser(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete user",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "User deleted successfully",
		"username": username,
	})
}

func ListDeletedUsersHandler(c *gin.Context) {
	deletedUsers, err := models.ListDeletedUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to fetch deleted user logs",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted_users": deletedUsers,
	})
}

// GetUserPermissionsHandler gets permissions for a specific user
func GetUserPermissionsHandler(c *gin.Context) {
	username := c.Param("username")

	user, err := models.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"username":    user.Username,
		"permissions": user.Permissions,
	})
}

// SetUserPermissionsHandler sets permissions for a specific user
func SetUserPermissionsHandler(c *gin.Context) {
	username := c.Param("username")

	var permData struct {
		Permissions map[string]string `json:"permissions" binding:"required"`
	}

	if err := c.ShouldBindJSON(&permData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	user, err := models.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var permSlice []models.Permission
	for component, permission := range permData.Permissions {
		if permission != "read" && permission != "write" && permission != "none" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission value. Must be 'read', 'write', or 'none'"})
			return
		}
		if permission != "none" {
			permSlice = append(permSlice, models.Permission{
				Component:  component,
				Permission: permission,
			})
		}
	}

	err = models.SetUserPermissions(user.ID, permSlice)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to set permissions",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Permissions updated successfully",
		"username":    username,
		"permissions": permData.Permissions,
	})
}

// ===================================
// Resource Component Handlers
// ===================================

func GetResourcesHandler(c *gin.Context) {
	// Mock data - replace with actual database queries
	resources := []gin.H{
		{"id": 1, "name": "Resource 1", "type": "server", "status": "active"},
		{"id": 2, "name": "Resource 2", "type": "database", "status": "inactive"},
	}
	c.JSON(http.StatusOK, gin.H{"resources": resources})
}

func GetResourceHandler(c *gin.Context) {
	id := c.Param("id")
	// Mock data - replace with actual database query
	resource := gin.H{"id": id, "name": "Resource " + id, "type": "server", "status": "active"}
	c.JSON(http.StatusOK, gin.H{"resource": resource})
}

// GetResourceByID - alias for individual resource access
func GetResourceByIDHandler(c *gin.Context) {
	GetResourceHandler(c)
}

func CreateResourceHandler(c *gin.Context) {
	var resourceData struct {
		Name string `json:"name" binding:"required"`
		Type string `json:"type" binding:"required"`
	}

	if err := c.ShouldBindJSON(&resourceData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Mock creation - replace with actual database insert
	c.JSON(http.StatusCreated, gin.H{
		"message": "Resource created successfully",
		"resource": gin.H{
			"id":   123,
			"name": resourceData.Name,
			"type": resourceData.Type,
		},
	})
}

func UpdateResourceHandler(c *gin.Context) {
	id := c.Param("id")
	var resourceData struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}

	if err := c.ShouldBindJSON(&resourceData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Mock update - replace with actual database update
	c.JSON(http.StatusOK, gin.H{
		"message": "Resource updated successfully",
		"id":      id,
	})
}

func DeleteResourceHandler(c *gin.Context) {
	id := c.Param("id")
	// Mock deletion - replace with actual database delete
	c.JSON(http.StatusOK, gin.H{
		"message": "Resource deleted successfully",
		"id":      id,
	})
}

// ===================================
// System Component Handlers
// ===================================

func GetSystemStatusHandler(c *gin.Context) {
	// Mock system status - replace with actual system checks
	status := gin.H{
		"status":     "healthy",
		"uptime":     "72h 15m",
		"cpu_usage":  "45%",
		"memory":     "67%",
		"disk_space": "23%",
	}
	c.JSON(http.StatusOK, gin.H{"system": status})
}

func GetSystemConfigHandler(c *gin.Context) {
	// Mock configuration - replace with actual config retrieval
	config := gin.H{
		"max_connections": 1000,
		"timeout":         30,
		"debug_mode":      false,
		"log_level":       "info",
	}
	c.JSON(http.StatusOK, gin.H{"config": config})
}

func UpdateSystemConfigHandler(c *gin.Context) {
	var configData map[string]interface{}

	if err := c.ShouldBindJSON(&configData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Mock config update - replace with actual config update
	c.JSON(http.StatusOK, gin.H{
		"message": "System configuration updated successfully",
		"config":  configData,
	})
}

func RestartSystemHandler(c *gin.Context) {
	// Mock system restart - replace with actual restart logic
	c.JSON(http.StatusOK, gin.H{"message": "System restart initiated"})
}

// ===================================
// Dashboard Component Handlers
// ===================================

func GetDashboardStatsHandler(c *gin.Context) {
	// Mock dashboard stats - replace with actual data
	stats := gin.H{
		"total_users":     42,
		"active_sessions": 15,
		"total_resources": 128,
		"alerts":          3,
	}
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

func GetDashboardChartsHandler(c *gin.Context) {
	// Mock chart data - replace with actual data
	charts := gin.H{
		"cpu_usage": []gin.H{
			{"time": "00:00", "value": 45},
			{"time": "01:00", "value": 52},
			{"time": "02:00", "value": 38},
		},
		"memory_usage": []gin.H{
			{"time": "00:00", "value": 67},
			{"time": "01:00", "value": 72},
			{"time": "02:00", "value": 69},
		},
	}
	c.JSON(http.StatusOK, gin.H{"charts": charts})
}

func CreateDashboardWidgetHandler(c *gin.Context) {
	var widgetData struct {
		Name string `json:"name" binding:"required"`
		Type string `json:"type" binding:"required"`
	}

	if err := c.ShouldBindJSON(&widgetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Mock widget creation - replace with actual database insert
	c.JSON(http.StatusCreated, gin.H{
		"message": "Dashboard widget created successfully",
		"widget": gin.H{
			"id":   456,
			"name": widgetData.Name,
			"type": widgetData.Type,
		},
	})
}

func UpdateDashboardWidgetHandler(c *gin.Context) {
	id := c.Param("id")
	var widgetData map[string]interface{}

	if err := c.ShouldBindJSON(&widgetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Mock widget update - replace with actual database update
	c.JSON(http.StatusOK, gin.H{
		"message": "Dashboard widget updated successfully",
		"id":      id,
	})
}

func DeleteDashboardWidgetHandler(c *gin.Context) {
	id := c.Param("id")
	// Mock widget deletion - replace with actual database delete
	c.JSON(http.StatusOK, gin.H{
		"message": "Dashboard widget deleted successfully",
		"id":      id,
	})
}

// GitHubLoginHandler initiates GitHub OAuth flow
func GitHubLoginHandler(c *gin.Context) {
	// Generate random state for CSRF protection
	state := generateStateToken()

	// Store state in session/cookie (you may want to use Redis or database)
	c.SetCookie("oauth_state", state, 600, "/", "", false, true)

	// Redirect to GitHub OAuth page
	url := githubOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GitHubCallbackHandler handles GitHub OAuth callback
func GitHubCallbackHandler(c *gin.Context) {
	// Verify state to prevent CSRF
	state := c.Query("state")
	savedState, err := c.Cookie("oauth_state")
	if err != nil || state != savedState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OAuth state"})
		return
	}

	// Clear the state cookie
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	// Get authorization code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code not provided"})
		return
	}

	// Exchange code for token
	ctx := context.Background()
	token, err := githubOAuthConfig.Exchange(ctx, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Get user info from GitHub
	githubUser, err := getGitHubUser(token.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info from GitHub"})
		return
	}

	// Get or create user in database
	user, err := getOrCreateGitHubUser(githubUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process user"})
		return
	}

	// Generate JWT tokens
	accessToken, refreshToken, err := issueTokens(user.ID, user.Username, user.IsAdmin, user.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Redirect to frontend with tokens (or send as JSON)
	// Option 1: Redirect with tokens in query params (less secure, for demo only)
	redirectURL := os.Getenv("FRONTEND_URL") + "/auth/callback?token=" + accessToken + "&refreshToken=" + refreshToken
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)

	// Option 2: Return JSON (more secure, requires frontend handling)
	// sendLoginResponse(c, accessToken, refreshToken, user.Username, user.IsAdmin, user.Permissions)
}

// GitHub user structure
type GitHubUser struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

// getGitHubUser fetches user info from GitHub API
func getGitHubUser(accessToken string) (*GitHubUser, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch GitHub user")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var githubUser GitHubUser
	if err := json.Unmarshal(body, &githubUser); err != nil {
		return nil, err
	}

	// If email is not public, fetch it separately
	if githubUser.Email == "" {
		email, _ := getGitHubUserEmail(accessToken)
		githubUser.Email = email
	}

	return &githubUser, nil
}

// getGitHubUserEmail fetches primary email from GitHub API
func getGitHubUserEmail(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch GitHub user emails")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	// Return primary verified email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	return "", errors.New("no verified email found")
}

// getOrCreateGitHubUser gets existing user or creates new one
func getOrCreateGitHubUser(githubUser *GitHubUser) (*models.User, error) {
	// Create unique username from GitHub login
	username := "github_" + githubUser.Login

	// Check if user exists
	user, err := models.GetUserByUsername(username)
	if err == nil && user != nil {
		// Update last login time
		query := `UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = $1`
		database.DB.Exec(query, user.ID)
		return user, nil
	}

	// Create new user
	// Generate random password (won't be used for GitHub SSO)
	randomPassword := generateRandomPassword(32)

	newUser, err := models.CreateUser(username, randomPassword, false)
	if err != nil {
		return nil, err
	}

	// Set default permissions for new SSO users
	defaultPermissions := []models.Permission{
		{Component: "dashboard", Permission: "read"},
		{Component: "resources", Permission: "read"},
	}

	if err := models.SetUserPermissions(newUser.ID, defaultPermissions); err != nil {
		return nil, err
	}

	// Store GitHub user info (optional: create oauth_users table)
	if err := storeGitHubUserInfo(newUser.ID, githubUser); err != nil {
		// Log error but don't fail the login
		println("Warning: Failed to store GitHub user info:", err.Error())
	}

	return newUser, nil
}

// storeGitHubUserInfo stores GitHub-specific user information
func storeGitHubUserInfo(userID int, githubUser *GitHubUser) error {
	query := `
        INSERT INTO oauth_users (user_id, provider, provider_user_id, email, avatar_url, name)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id, provider) 
        DO UPDATE SET 
            provider_user_id = EXCLUDED.provider_user_id,
            email = EXCLUDED.email,
            avatar_url = EXCLUDED.avatar_url,
            name = EXCLUDED.name,
            updated_at = CURRENT_TIMESTAMP
    `

	_, err := database.DB.Exec(query, userID, "github", githubUser.ID,
		githubUser.Email, githubUser.AvatarURL, githubUser.Name)
	return err
}

// Helper functions
func generateStateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateRandomPassword(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
