const express = require('express');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const app = express();
const port = 3000;

// Import routes
const scanRoutes = require('./routes/scan');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, '../public')));

// Use routes
app.use('/api', scanRoutes);

// Main route
app.get('/', (req, res) => {
    const htmlPath = path.join(__dirname, '../public', 'index.html');
    console.log('📁 Serving HTML from:', htmlPath);
    
    if (fs.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.status(404).send('index.html not found');
    }
});

// Simple debug route
app.get('/debug', (req, res) => {
    const publicPath = path.join(__dirname, '../public');
    const pythonPath = path.join(__dirname, '../python-scanner');
    
    const debug = {
        server_time: new Date().toISOString(),
        server_port: port,
        directories: {
            public: {
                path: publicPath,
                exists: fs.existsSync(publicPath),
                files: fs.existsSync(publicPath) ? fs.readdirSync(publicPath) : []
            },
            python: {
                path: pythonPath,
                exists: fs.existsSync(pythonPath),
                files: fs.existsSync(pythonPath) ? fs.readdirSync(pythonPath) : []
            }
        },
        file_checks: {
            index_html: fs.existsSync(path.join(publicPath, 'index.html')),
            style_css: fs.existsSync(path.join(publicPath, 'style.css')),
            script_js: fs.existsSync(path.join(publicPath, 'script.js')),
            nmap_scanner: fs.existsSync(path.join(pythonPath, 'nmap_scanner.py'))
        }
    };
    
    res.json(debug);
});

// Route to directly check CSS
app.get('/test-css', (req, res) => {
    const cssPath = path.join(__dirname, '../public', 'style.css');
    
    let html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSS Test</title>
            <link rel="stylesheet" href="/style.css">
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                .success { color: green; font-weight: bold; }
                .error { color: red; font-weight: bold; }
                .info { background: #f0f0f0; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>🎨 CSS Test Page</h1>
            <hr>
            <h2>Visual Test:</h2>
            <p class="success">✅ If this text is GREEN, CSS is working!</p>
            <p class="error">❌ If this text is RED, CSS is NOT working!</p>
            
            <hr>
            <h2>Debug Information:</h2>
            <div class="info">
    `;
    
    if (fs.existsSync(cssPath)) {
        const stats = fs.statSync(cssPath);
        html += `
            <p>✅ CSS file found at: ${cssPath}</p>
            <p>📊 File size: ${stats.size} bytes</p>
            <p>🕒 Last modified: ${stats.mtime}</p>
        `;
    } else {
        html += `
            <p>❌ CSS file NOT found at: ${cssPath}</p>
            <p>🔍 Please check if style.css exists in the public folder</p>
        `;
    }
    
    html += `
            </div>
            <hr>
            <p>
                <a href="/">🏠 Back to Main App</a> | 
                <a href="/style.css">📄 View CSS directly</a> | 
                <a href="/debug">🔧 Debug Info</a>
            </p>
        </body>
        </html>
    `;
    
    res.send(html);
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err.stack);
    res.status(500).json({ 
        error: 'Something went wrong!',
        message: err.message 
    });
});

// 404 handler
app.use((req, res) => {
    console.log('❌ 404 - Route not found:', req.url);
    res.status(404).json({ 
        error: 'Route not found',
        path: req.url 
    });
});

// Start server
app.listen(port, () => {
    console.log('\n' + '='.repeat(60));
    console.log('🚀 SMART URL RISK ANALYZER WITH NMAP');
    console.log('='.repeat(60));
    console.log(`📍 Server URL: http://localhost:${port}`);
    console.log(`📁 Public folder: ${path.join(__dirname, '../public')}`);
    console.log(`🐍 Python folder: ${path.join(__dirname, '../python-scanner')}`);
    console.log('-'.repeat(60));
    
    // Check public directory
    const publicPath = path.join(__dirname, '../public');
    if (fs.existsSync(publicPath)) {
        console.log('✅ Public directory found');
        
        // Check required files
        const files = fs.readdirSync(publicPath);
        console.log('\n📄 Files in public folder:');
        files.forEach(file => {
            const filePath = path.join(publicPath, file);
            const stats = fs.statSync(filePath);
            const checkmark = file === 'style.css' ? '🎨' : (file === 'index.html' ? '📄' : (file === 'script.js' ? '⚡' : '📁'));
            console.log(`   ${checkmark} ${file} (${stats.size} bytes)`);
        });
        
        // Check for required files
        console.log('\n✅ Required files check:');
        const cssExists = fs.existsSync(path.join(publicPath, 'style.css'));
        const htmlExists = fs.existsSync(path.join(publicPath, 'index.html'));
        const jsExists = fs.existsSync(path.join(publicPath, 'script.js'));
        
        console.log(`   ${cssExists ? '✅' : '❌'} style.css`);
        console.log(`   ${htmlExists ? '✅' : '❌'} index.html`);
        console.log(`   ${jsExists ? '✅' : '❌'} script.js`);
        
        if (!cssExists) {
            console.log('\n⚠️  WARNING: style.css is missing!');
            console.log('   Create it at: ' + path.join(publicPath, 'style.css'));
        }
    } else {
        console.log('❌ Public directory NOT found!');
        console.log('   Please create it at: ' + publicPath);
    }
    
    // Check python scanner
    const pythonPath = path.join(__dirname, '../python-scanner');
    if (fs.existsSync(pythonPath)) {
        const pythonFiles = fs.readdirSync(pythonPath);
        const nmapExists = pythonFiles.includes('nmap_scanner.py');
        console.log('\n🐍 Python scanner check:');
        console.log(`   ${nmapExists ? '✅' : '❌'} nmap_scanner.py`);
        
        if (nmapExists) {
            console.log('   📁 Python files:', pythonFiles.join(', '));
        }
    } else {
        console.log('\n❌ Python scanner directory NOT found!');
    }
    
    console.log('-'.repeat(60));
    console.log('🔗 Test URLs:');
    console.log(`   • Main App: http://localhost:${port}`);
    console.log(`   • CSS Test: http://localhost:${port}/test-css`);
    console.log(`   • Debug Info: http://localhost:${port}/debug`);
    console.log(`   • View CSS: http://localhost:${port}/style.css`);
    console.log('='.repeat(60) + '\n');
});