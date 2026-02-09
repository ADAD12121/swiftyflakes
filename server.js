// ========================================
// SWIFT NOTIFIER BACKEND - ULTRA FAST MODE
// 10-second retention - Optimized for real-time scanning
// ========================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for deployment behind reverse proxies (Render, etc.)
app.set('trust proxy', 1);

// ========================================
// CONFIGURATION
// ========================================

const CONFIG = {
  RETENTION_SECONDS: 10,
  CLEANUP_INTERVAL: 5,
  MAX_PETS_PER_FINDING: 100,
  MAX_PET_LENGTH: 200,
  MAX_QUERY_LIMIT: 500,
  DEFAULT_QUERY_LIMIT: 100,
  DB_BUSY_TIMEOUT: 5000,
  JSON_SIZE_LIMIT: '1mb'
};

// ========================================
// MIDDLEWARE
// ========================================

// Security headers
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Response compression
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// CORS configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key'],
  credentials: false,
  maxAge: 86400
}));

// Body parsing
app.use(express.json({ limit: CONFIG.JSON_SIZE_LIMIT, strict: true }));
app.use(express.urlencoded({ extended: true, limit: CONFIG.JSON_SIZE_LIMIT }));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (duration > 1000) {
      console.warn(`⚠️ Slow request: ${req.method} ${req.path} - ${duration}ms`);
    }
  });
  next();
});

// ========================================
// DATABASE SETUP
// ========================================

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'findings.db');
let db;

function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        console.error('❌ Database connection failed:', err.message);
        reject(err);
      } else {
        console.log('✅ Connected to SQLite database');
        
        // Enable WAL mode for better concurrent performance
        db.run('PRAGMA journal_mode = WAL');
        db.run('PRAGMA synchronous = NORMAL');
        db.run('PRAGMA cache_size = 10000');
        db.run('PRAGMA temp_store = MEMORY');
        db.configure('busyTimeout', CONFIG.DB_BUSY_TIMEOUT);
        
        resolve();
      }
    });
  });
}

function createTables() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Create findings table
      db.run(`
        CREATE TABLE IF NOT EXISTS findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          jobId TEXT NOT NULL,
          placeId TEXT NOT NULL,
          pets TEXT NOT NULL,
          rates TEXT,
          timestamp INTEGER NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(jobId, placeId)
        )
      `, (err) => {
        if (err) {
          console.error('❌ Table creation failed:', err.message);
          reject(err);
        } else {
          console.log('✅ Findings table ready');
        }
      });

      // Create indexes
      db.run('CREATE INDEX IF NOT EXISTS idx_timestamp ON findings(timestamp DESC)', (err) => {
        if (err) console.error('❌ Index creation failed (timestamp):', err.message);
      });
      
      db.run('CREATE INDEX IF NOT EXISTS idx_jobId ON findings(jobId)', (err) => {
        if (err) console.error('❌ Index creation failed (jobId):', err.message);
        else resolve();
      });
    });
  });
}

function startCleanupJob() {
  console.log(`🧹 Starting cleanup job (every ${CONFIG.CLEANUP_INTERVAL}s)`);
  
  setInterval(() => {
    const cutoffTime = Date.now() - (CONFIG.RETENTION_SECONDS * 1000);
    
    db.run('DELETE FROM findings WHERE timestamp < ?', [cutoffTime], function(err) {
      if (err) {
        console.error('❌ Cleanup failed:', err.message);
      } else if (this.changes > 0) {
        console.log(`🧹 Cleaned up ${this.changes} old findings (>${CONFIG.RETENTION_SECONDS}s)`);
      }
    });
  }, CONFIG.CLEANUP_INTERVAL * 1000);
}

// ========================================
// VALIDATION HELPERS
// ========================================

function validateFinding(data) {
  // Validate jobId
  if (!data.jobId || typeof data.jobId !== 'string' || data.jobId.trim().length === 0) {
    return { valid: false, error: 'Invalid or missing jobId' };
  }
  
  if (data.jobId.length > 255) {
    return { valid: false, error: 'jobId too long (max 255 characters)' };
  }

  // Validate placeId
  if (!data.placeId || typeof data.placeId !== 'string' || data.placeId.trim().length === 0) {
    return { valid: false, error: 'Invalid or missing placeId' };
  }
  
  if (data.placeId.length > 255) {
    return { valid: false, error: 'placeId too long (max 255 characters)' };
  }

  // Validate pets array
  if (!Array.isArray(data.pets)) {
    return { valid: false, error: 'pets must be an array' };
  }
  
  if (data.pets.length === 0) {
    return { valid: false, error: 'pets array cannot be empty' };
  }
  
  if (data.pets.length > CONFIG.MAX_PETS_PER_FINDING) {
    return { valid: false, error: `Too many pets (max ${CONFIG.MAX_PETS_PER_FINDING})` };
  }

  // Sanitize pets
  const sanitizedPets = data.pets
    .filter(pet => typeof pet === 'string' && pet.trim().length > 0)
    .map(pet => pet.trim().substring(0, CONFIG.MAX_PET_LENGTH))
    .filter((pet, index, self) => self.indexOf(pet) === index); // Remove duplicates
  
  if (sanitizedPets.length === 0) {
    return { valid: false, error: 'No valid pets after sanitization' };
  }

  // Validate rates (optional)
  if (data.rates !== undefined && data.rates !== null) {
    if (typeof data.rates !== 'object') {
      return { valid: false, error: 'rates must be an object' };
    }
  }
  
  return { 
    valid: true, 
    sanitized: {
      jobId: data.jobId.trim(),
      placeId: data.placeId.trim(),
      pets: sanitizedPets,
      rates: data.rates
    }
  };
}

function validateQueryParams(query) {
  const limit = parseInt(query.limit) || CONFIG.DEFAULT_QUERY_LIMIT;
  const minTimestamp = parseInt(query.minTimestamp) || 0;
  
  return {
    limit: Math.max(1, Math.min(limit, CONFIG.MAX_QUERY_LIMIT)),
    minTimestamp: Math.max(0, minTimestamp)
  };
}

// ========================================
// API ENDPOINTS
// ========================================

// Health check endpoint
app.get('/health', (req, res) => {
  db.get('SELECT COUNT(*) as count FROM findings', (err, row) => {
    if (err) {
      return res.status(503).json({ 
        status: 'error',
        error: 'Database unavailable'
      });
    }

    res.json({ 
      status: 'ok',
      service: 'Swift Notifier',
      version: '2.0.0',
      uptime: Math.floor(process.uptime()),
      timestamp: Date.now(),
      database: {
        activeFindings: row ? row.count : 0,
        retentionSeconds: CONFIG.RETENTION_SECONDS
      },
      memory: {
        heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
        heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
      }
    });
  });
});

// Submit finding endpoint
app.post('/api/submit', async (req, res) => {
  try {
    const validation = validateFinding(req.body);
    
    if (!validation.valid) {
      return res.status(400).json({ 
        success: false, 
        error: validation.error 
      });
    }

    const { jobId, placeId, pets, rates } = validation.sanitized;
    const timestamp = Date.now();
    const petsJson = JSON.stringify(pets);
    const ratesJson = rates ? JSON.stringify(rates) : null;

    db.run(
      `INSERT INTO findings (jobId, placeId, pets, rates, timestamp) 
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(jobId, placeId) 
       DO UPDATE SET 
         pets = excluded.pets,
         rates = excluded.rates,
         timestamp = excluded.timestamp`,
      [jobId, placeId, petsJson, ratesJson, timestamp],
      function(err) {
        if (err) {
          console.error('❌ Database insert failed:', err.message);
          return res.status(500).json({ 
            success: false, 
            error: 'Database error' 
          });
        }

        console.log(`✅ ${pets.length} pet${pets.length !== 1 ? 's' : ''} | Job: ${jobId.substring(0, 12)}... | Place: ${placeId.substring(0, 12)}...`);
        
        res.json({ 
          success: true, 
          message: 'Finding stored successfully',
          data: {
            id: this.lastID,
            timestamp,
            expiresIn: CONFIG.RETENTION_SECONDS,
            petsCount: pets.length
          }
        });
      }
    );

  } catch (error) {
    console.error('❌ Submit error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// Query pets endpoint
app.get('/api/pets', (req, res) => {
  try {
    const { limit, minTimestamp } = validateQueryParams(req.query);

    db.all(
      `SELECT jobId, placeId, pets, rates, timestamp 
       FROM findings 
       WHERE timestamp >= ?
       ORDER BY timestamp DESC 
       LIMIT ?`,
      [minTimestamp, limit],
      (err, rows) => {
        if (err) {
          console.error('❌ Database query failed:', err.message);
          return res.status(500).json({ 
            success: false, 
            error: 'Database error' 
          });
        }

        const findings = rows.map(row => {
          try {
            return {
              jobId: row.jobId,
              placeId: row.placeId,
              pets: JSON.parse(row.pets),
              rates: row.rates ? JSON.parse(row.rates) : null,
              timestamp: row.timestamp,
              age: Math.floor((Date.now() - row.timestamp) / 1000) // Age in seconds
            };
          } catch (parseError) {
            console.error('❌ JSON parse error:', parseError.message);
            return null;
          }
        }).filter(finding => finding !== null);

        res.json({ 
          success: true, 
          data: findings,
          meta: {
            count: findings.length,
            limit,
            minTimestamp,
            serverTime: Date.now()
          }
        });
      }
    );

  } catch (error) {
    console.error('❌ Query error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// Statistics endpoint
app.get('/api/stats', (req, res) => {
  db.get(
    `SELECT 
      COUNT(*) as total,
      MIN(timestamp) as oldestTimestamp,
      MAX(timestamp) as newestTimestamp
     FROM findings`,
    (err, row) => {
      if (err) {
        console.error('❌ Stats query failed:', err.message);
        return res.status(500).json({ 
          success: false, 
          error: 'Database error' 
        });
      }

      const now = Date.now();
      res.json({
        success: true,
        data: {
          totalFindings: row.total,
          oldestAge: row.oldestTimestamp ? Math.floor((now - row.oldestTimestamp) / 1000) : null,
          newestAge: row.newestTimestamp ? Math.floor((now - row.newestTimestamp) / 1000) : null,
          retentionSeconds: CONFIG.RETENTION_SECONDS
        },
        server: {
          uptime: Math.floor(process.uptime()),
          memory: {
            heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
            rss: Math.round(process.memoryUsage().rss / 1024 / 1024) + 'MB'
          },
          timestamp: now
        }
      });
    }
  );
});

// Clear all findings (admin only)
app.delete('/api/clear', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const validKey = process.env.ADMIN_API_KEY || 'your-secret-key-here';
  
  if (!apiKey || apiKey !== validKey) {
    return res.status(403).json({ 
      success: false, 
      error: 'Unauthorized - Invalid or missing API key' 
    });
  }

  db.run('DELETE FROM findings', function(err) {
    if (err) {
      console.error('❌ Clear operation failed:', err.message);
      return res.status(500).json({ 
        success: false, 
        error: 'Database error' 
      });
    }

    console.log(`🗑️ All findings cleared (${this.changes} rows deleted)`);
    res.json({ 
      success: true, 
      message: 'All findings cleared',
      rowsDeleted: this.changes
    });
  });
});

// ========================================
// ERROR HANDLING
// ========================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found',
    path: req.path,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  
  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({ 
    success: false, 
    error: isDevelopment ? err.message : 'Internal server error',
    ...(isDevelopment && { stack: err.stack })
  });
});

// ========================================
// GRACEFUL SHUTDOWN
// ========================================

function gracefulShutdown(signal) {
  console.log(`\n📴 Received ${signal}, shutting down gracefully...`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    
    db.close((err) => {
      if (err) {
        console.error('❌ Error closing database:', err.message);
        process.exit(1);
      } else {
        console.log('✅ Database connection closed');
        process.exit(0);
      }
    });
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('⚠️ Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// ========================================
// SERVER STARTUP
// ========================================

let server;

async function startServer() {
  try {
    await initializeDatabase();
    await createTables();
    startCleanupJob();
    
    server = app.listen(PORT, '0.0.0.0', () => {
      console.log('');
      console.log('========================================');
      console.log('🚀 SWIFT NOTIFIER - ULTRA FAST MODE');
      console.log('========================================');
      console.log(`📡 Port: ${PORT}`);
      console.log(`💾 Database: ${DB_PATH}`);
      console.log(`⏱️  Retention: ${CONFIG.RETENTION_SECONDS} seconds`);
      console.log(`🧹 Cleanup: Every ${CONFIG.CLEANUP_INTERVAL} seconds`);
      console.log(`🔒 Security: Helmet, CORS enabled`);
      console.log(`📦 Compression: Enabled`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log('========================================');
      console.log('');
    });
    
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
}

// Start the server
startServer();

module.exports = app;
