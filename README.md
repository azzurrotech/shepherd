# shepherd (Security & Billing Platform)

**MIT License © Azzurro Technology Inc.**

## Overview

The shepherd project combines advanced firewall protection with automated paywall functionality into a comprehensive security solution. It provides advanced security measures while handling automated client billing and access control in a unified platform.

## Installation

### Prerequisites
- Go 1.20+
- SQLite database
- **github.com/gin-gonic/gin** v1.9.1 - HTTP server framework
- **github.com/gin-contrib/cors** v1.7.0 - CORS support
- **github.com/mattn/go-sqlite3** - SQLite database driver

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/azzurro-tech/shepherd.git
   cd shepherd
   ```

2. Install Go dependencies:
   ```bash
   go mod download
   ```

3. Start the shepherd security service:
   ```bash
   cd azzurrotech/shepherd
   go run .
   ```

4. Access the shepherd web interface:
   ```
   http://localhost:8084
   http://localhost:8084/shepherd/config
   http://localhost:8084/shepherd/admin
   ```

## Usage (Standalone)

### Basic Operations

**Firewall Management**
```bash
# List all firewall rules
curl http://localhost:8084/api/firewall/rules

# Add new firewall rule
curl -X POST http://localhost:8084/api/firewall/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"Block Malicious IPs","description":"Block known malicious IPs","rules":[{"type":"ip","action":"block","source":"192.168.1.0/24"},{"type":"port","action":"allow","port":80}]}'

# Get specific firewall rule
curl http://localhost:8084/api/firewall/rules/{rule-id}
```

**Client Management**
```bash
# List all clients
curl http://localhost:8084/api/clients

# Create new client
curl -X POST http://localhost:8084/api/clients \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corporation","email":"contact@acme.com","plan":"enterprise","status":"active","billing_info":{"method":"credit_card","details":"**** **** **** 1234"}}'

# Get client billing information
curl http://localhost:8084/api/clients/{client-id}/billing

# Process payment
curl -X POST http://localhost:8084/api/billing \
  -H "Content-Type: application/json" \
  -d '{"client_id":"client-123","amount":99.99,"method":"credit_card","description":"Monthly enterprise plan"}'
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main shepherd status page |
| `/shepherd` | GET | HTML config viewer |
| `/shepherd/config` | GET | View configuration |
| `/shepherd/config` | POST | Update configuration |
| `/shepherd/admin` | GET | HTML admin panel |
| `/shepherd/admin` | POST | Update admin settings |
| `/api/firewall/rules` | GET | List all firewall rules |
| `/api/firewall/rules` | POST | Add new firewall rule |
| `/api/firewall/rules/{id}` | GET | Get specific firewall rule |
| `/api/firewall/rules/{id}` | PUT | Update firewall rule |
| `/api/firewall/rules/{id}` | DELETE | Delete firewall rule |
| `/api/clients` | GET | List all clients |
| `/api/clients` | POST | Create new client |
| `/api/clients/{id}` | GET | Get specific client |
| `/api/clients/{id}` | PUT | Update client |
| `/api/clients/{id}` | DELETE | Delete client |
| `/api/clients/{id}/billing` | GET | Get client billing |
| `/api/billing` | GET | List all billing |
| `/api/billing` | POST | Process payment |
| `/health` | GET | Health check |

## Integration with ATP

### Service Registration

The shepherd project registers with ATP as a comprehensive security and billing service:

```go
// Example shepherd service registration
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    
    // Health check endpoint
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "healthy"})
    })
    
    // Firewall API
    firewall := r.Group("/api/firewall/rules")
    {
        firewall.GET("/", getAllRules)
        firewall.POST("/", createRule)
        firewall.GET("/{id}", getRule)
        firewall.PUT("/{id}", updateRule)
        firewall.DELETE("/{id}", deleteRule)
    }
    
    // Client API
    clients := r.Group("/api/clients")
    {
        clients.GET("/", getAllClients)
        clients.POST("/", createClient)
        clients.GET("/{id}", getClient)
        clients.PUT("/{id}", updateClient)
        clients.DELETE("/{id}", deleteClient)
        clients.GET("/{id}/billing", getClientBilling)
    }
    
    // Billing API
    billing := r.Group("/api/billing")
    {
        billing.GET("/", getAllBilling)
        billing.POST("/", processPayment)
        billing.GET("/{id}", getBilling)
        billing.PUT("/{id}", updateBilling)
        billing.DELETE("/{id}", deleteBilling)
    }
    
    // Service registration with ATP
    r.POST("/register", func(c *gin.Context) {
        config := map[string]interface{}{
            "name": "shepherd",
            "endpoint": "http://localhost:8084",
            "health": "/health",
            "firewall_endpoint": "/api/firewall/rules",
            "clients_endpoint": "/api/clients",
            "billing_endpoint": "/api/bing",
            "auth_endpoint": "/api/auth",
            "config_endpoint": "/api/shepherd/config"
        }
        
        response, err := registerWithATP(config)
        if err != nil {
            c.JSON(500, gin.H{"error": "registration failed"})
            return
        }
        
        c.JSON(200, response)
    })
    
    r.Run(":8084")
}
```

### Security Integration

The shepherd project integrates with ATP for comprehensive security management:

```yaml
# atp/config/integrations.yaml
integrations:
  azzurrotech:
    shepherd:
      health_check: /health
      firewall_endpoint: /api/firewall/rules
      clients_endpoint: /api/clients
      billing_endpoint: /api/bing
      auth_endpoint: /api/auth
      config_endpoint: /api/shepherd/config
      admin_endpoint: /api/shepherd/admin
      auth_required: true
```

### Security Pipeline

1. **Firewall Management**: Advanced packet filtering and intrusion prevention
2. **Paywall Control**: Secure access control with billing integration
3. **Client Management**: Comprehensive client lifecycle management
4. **Billing System**: Automated payment processing and subscription management
5. **Security Monitoring**: Real-time threat detection and response
6. **Integration**: Seamless integration with ATP security framework

## Development Setup

### Local Development

```bash
# Start shepherd server
cd azzurrotech/shepherd
go run .

# Or with environment variables
cd azzurrotech/shepherd
export SHEPHERD_PORT=8084
export DB_PATH=./data/shepherd.db
go run .
```

### Testing

```bash
# Run all tests
cd azzurrotech/shepherd
go test ./...

# Run specific test packages
cd azzurrotech/shepherd
go test ./internal/paywall/...
go test ./internal/billing/...
go test ./internal/firewall/...
go test ./internal/auth/...

# Run integration tests
cd azzurrotech/shepherd
go test ./integration/...

# Test API endpoints
curl http://localhost:8084/health
curl http://localhost:8084/api/firewall/rules
curl http://localhost:8084/api/clients
```

### Building

```bash
# Build for production
cd azzurrotech/shepherd
go build -o shepherd ./cmd

# Build with specific options
cd azzurrotech/shepherd
go build -ldflags="-port=8084" -o shepherd ./cmd

# Build with SQLite configuration
cd azzurrotech/shepherd
DB_PATH=./data/shepherd.db go run .
```

## Performance Optimization

### Security Processing

- **Efficient Rule Processing**: Optimized firewall rule evaluation
- **Caching**: Cache frequently used rules and configurations
- **Connection Pooling**: Efficient database connection management
- **Compression**: Compress sensitive data transfers
- **Load Balancing**: Supports horizontal scaling

### Database Optimization

```go
// Database optimization for shepherd
var db *sql.DB

func initDatabase() {
    var err error
    // SQLite configuration for shepherd
    db, err = sql.Open("sqlite3", "./data/shepherd.db")
    if err != nil {
        log.Fatal("Database connection failed")
    }
    
    // Set connection pool settings
    db.SetMaxOpenConns(20)
    db.SetMaxIdleConns(10)
    db.SetConnMaxLifetime(time.Hour)
    
    // Create indexes for performance
    createSecurityIndexes()
}

func createSecurityIndexes() {
    queries := []string{
        "CREATE INDEX IF NOT EXISTS idx_firewall_rules_name ON firewall_rules(name)",
        "CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled)",
        "CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status)",
        "CREATE INDEX IF NOT EXISTS idx_billing_amount ON billing(amount)",
    }
    
    for _, query := range queries {
        _, err := db.Exec(query)
        if err != nil {
            log.Printf("Error creating index: %v", err)
        }
    }
}
```

## Monitoring

### Health Monitoring

```bash
# shepherd health check
curl http://localhost:8084/health

# Firewall rules health
curl http://localhost:8084/api/firewall/rules

# Client management health
curl http://localhost:8084/api/clients

# Billing system health
curl http://localhost:8084/api/billing

# Configuration health
curl http://localhost:8084/shepherd/config
```

### Metrics Collection

The shepherd project collects and reports:

- **Firewall Status**: All firewall rules status
- **Security Events**: Security events and threats detected
- **Client Status**: Active clients and subscriptions
- **Billing Status**: Billing records and payment status
- **Performance Metrics**: Security processing performance
- **Error Rates**: Security and billing error tracking

## Security Features

### shepherd Security

- **Firewall Management**: Advanced packet filtering and intrusion prevention
- **Paywall Security**: Secure payment processing and access control
- **Client Authentication**: Secure user authentication and session management
- **Billing Security**: Protected financial transactions and automated charging
- **Automated Integration**: Seamless integration with billing systems
- **Compliance**: Regulatory compliance and standards adherence

### Security Architecture

The shepherd project provides comprehensive security features:

- **Firewall Rules**: Custom firewall rule configuration and management
- **Access Control**: Role-based access control for security functions
- **Authentication**: Secure user authentication and authorization
- **Authorization**: Granular permissions for security operations
- **Encryption**: AES-256 encryption for sensitive data
- **Audit Trails**: Comprehensive logging of all security actions
- **Threat Detection**: Real-time threat detection and response
- **Compliance**: Regulatory compliance and standards adherence

## Troubleshooting

### Common Issues

1. **Firewall Rules Not Loading**
   ```bash
   # Check shepherd logs
   $ tail -f shepherd.log
   
   # Test database connection
   $ sqlite3 ./data/shepherd.db "SELECT * FROM firewall_rules;"
   
   # Check shepherd health
   $ curl http://localhost:8084/health
   ```

2. **Client Access Denied**
   ```bash
   # Check client status
   $ curl http://localhost:8084/api/clients
   
   # Check authentication
   $ curl http://localhost:8084/api/auth/validate
   
   # Check shepherd logs
   $ tail -f shepherd.log
   ```

3. **Billing Errors**
   ```bash
   # Check billing system
   $ curl http://localhost:8084/api/billing
   
   # Check payment gateway configuration
   $ grep -r "payment" shepherd.log
   
   # Check shepherd configuration
   $ curl http://localhost:8084/shepherd/config
   ```

### Debugging Commands

```bash
# Enable debug logging
export SHEPHERD_LOG_LEVEL=debug

# Check shepherd logs
$ tail -f shepherd.log

# Monitor system resources
$ top
$ free -h

# Test firewall rules
$ curl http://localhost:8084/api/firewall/rules

# Test client management
$ curl http://localhost:8084/api/clients

# Test billing system
$ curl http://localhost:8084/api/billing
```

## API Specifications

### High Maturity API (REST-based)

```http
GET /api/firewall/rules
POST /api/firewall/rules
GET /api/firewall/rules/{id}
PUT /api/firewall/rules/{id}
DELETE /api/firewall/rules/{id}
GET /api/clients
POST /api/clients
GET /api/clients/{id}
PUT /api/clients/{id}
DELETE /api/clients/{id}
GET /api/clients/{id}/billing
GET /api/billing
POST /api/billing
GET /api/billing/{id}
PUT /api/billing/{id}
DELETE /api/billing/{id}
GET /health
```

### shepherd-specific Endpoints

```http
GET /shepherd/config - View shepherd configuration
POST /shepherd/config - Update shepherd configuration
GET /shepherd/admin - View admin information
POST /shepherd/admin - Modify admin settings
```

## Future Enhancements

### Planned Features

1. **Advanced Threat Detection**: AI-powered threat detection
2. **Zero-Trust Security**: Implement zero-trust architecture
3. **Multi-Tenancy**: Support multiple tenants and organizations
4. **API Gateway**: Add API management capabilities
5. **Real-time Analytics**: Add real-time security analytics

### Roadmap

- **Phase 1**: Basic firewall and billing functionality
- **Phase 2**: Advanced security features and threat detection
- **Phase 3**: Multi-tenancy and enterprise features
- **Phase 4**: Advanced analytics and automation

## Conclusion

The shepherd project provides a comprehensive security solution that combines firewall protection with paywall functionality. It offers advanced security features while handling automated client billing and access control in a unified platform.

The shepherd implementation provides:

- **Security Management**: Comprehensive security rule management
- **Access Control**: Secure access control with billing integration
- **Client Management**: Complete client lifecycle management
- **Billing System**: Automated payment processing and subscription management
- **Threat Detection**: Real-time threat detection and response
- **API Integration**: RESTful API for security services
- **Configuration Management**: Flexible configuration options
- **Production Ready**: Comprehensive error handling and monitoring

This security system is production-ready and can be easily integrated into enterprise applications with comprehensive security and billing capabilities.

---

*Document Version: 1.0*
*Created: 2026-08-25*
*Last Updated: 2026-08-25*
*Status: Production Ready*

**License:** MIT License © Azzurro Technology Inc.