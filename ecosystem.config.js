module.exports = {
  apps: [{
    name: 'nexus',
    script: 'server.js',
    instances: 1,          // SQLite is single-writer; keep at 1
    autorestart: true,
    watch: false,
    max_memory_restart: '512M',
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      JWT_SECRET: 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET'
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss'
  }]
};
