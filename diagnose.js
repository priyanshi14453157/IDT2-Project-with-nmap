const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

console.log('\n🔍 ==================================');
console.log('🔍 WEBSITE SECURITY SCANNER DIAGNOSTIC');
console.log('🔍 ==================================\n');

// Check current directory
console.log(`📁 Current directory: ${process.cwd()}`);
console.log(`📁 Script location: ${__dirname}\n`);

// Define paths
const rootDir = path.join(__dirname, '..');
const publicDir = path.join(rootDir, 'public');
const pythonDir = path.join(rootDir, 'python-scanner');
const backendDir = __dirname;

console.log('📂 PROJECT STRUCTURE CHECK:');
console.log('----------------------------------------');
console.log(`Root directory: ${rootDir}`);
console.log(`Root exists: ${fs.existsSync(rootDir) ? '✅' : '❌'}`);
console.log(`Public directory: ${publicDir}`);
console.log(`Public exists: ${fs.existsSync(publicDir) ? '✅' : '❌'}`);
console.log(`Python directory: ${pythonDir}`);
console.log(`Python exists: ${fs.existsSync(pythonDir) ? '✅' : '❌'}`);
console.log(`Backend directory: ${backendDir}`);
console.log(`Backend exists: ${fs.existsSync(backendDir) ? '✅' : '❌'}\n`);

// Check public directory contents
if (fs.existsSync(publicDir)) {
    console.log('📄 PUBLIC DIRECTORY FILES:');
    console.log('----------------------------------------');
    const files = fs.readdirSync(publicDir);
    
    if (files.length === 0) {
        console.log('❌ No files found in public directory!');
    } else {
        files.forEach(file => {
            const filePath = path.join(publicDir, file);
            const stats = fs.statSync(filePath);
            const isCss = file.endsWith('.css');
            const isHtml = file.endsWith('.html');
            const isJs = file.endsWith('.js');
            
            let icon = '📄';
            if (isCss) icon = '🎨';
            if (isHtml) icon = '🌐';
            if (isJs) icon = '⚡';
            
            console.log(`${icon} ${file} (${stats.size} bytes)`);
            
            // Check if CSS file has content
            if (isCss) {
                const content = fs.readFileSync(filePath, 'utf8');
                console.log(`   └─ Content length: ${content.length} chars`);
                if (content.length < 10) {
                    console.log(`   └─ ⚠️  CSS file appears to be empty!`);
                }
            }
        });
    }
    
    // Check for required files
    console.log('\n✅ REQUIRED FILES CHECK:');
    const htmlExists = fs.existsSync(path.join(publicDir, 'index.html'));
    const cssExists = fs.existsSync(path.join(publicDir, 'style.css'));
    const jsExists = fs.existsSync(path.join(publicDir, 'script.js'));
    
    console.log(`index.html: ${htmlExists ? '✅' : '❌'}`);
    console.log(`style.css: ${cssExists ? '✅' : '❌'}`);
    console.log(`script.js: ${jsExists ? '✅' : '❌'}`);
    
    // If CSS is missing but HTML has inline styles, that's fine
    if (!cssExists) {
        console.log('\nℹ️  Note: If you have inline CSS in index.html, style.css is optional');
        
        // Check if HTML has inline styles
        if (htmlExists) {
            const htmlContent = fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8');
            if (htmlContent.includes('<style>')) {
                console.log('✅ Found inline CSS in index.html!');
            } else {
                console.log('❌ No inline CSS found in index.html');
            }
        }
    }
} else {
    console.log('❌ Public directory not found!');
    console.log(`   Please create it at: ${publicDir}`);
}

// Check Python scanner
console.log('\n🐍 PYTHON SCANNER CHECK:');
console.log('----------------------------------------');
if (fs.existsSync(pythonDir)) {
    const pyFiles = fs.readdirSync(pythonDir);
    const scannerExists = pyFiles.includes('nmap_scanner.py');
    const reqExists = pyFiles.includes('requirements.txt');
    
    console.log(`nmap_scanner.py: ${scannerExists ? '✅' : '❌'}`);
    console.log(`requirements.txt: ${reqExists ? '✅' : '❌'}`);
    
    if (scannerExists) {
        console.log('\n📄 Python scanner first 5 lines:');
        const scannerPath = path.join(pythonDir, 'nmap_scanner.py');
        const content = fs.readFileSync(scannerPath, 'utf8');
        const lines = content.split('\n').slice(0, 5);
        lines.forEach(line => console.log(`   ${line}`));
    }
} else {
    console.log('❌ Python scanner directory not found!');
}

// Check Node.js dependencies
console.log('\n📦 NODE.JS DEPENDENCIES:');
console.log('----------------------------------------');
const packagePath = path.join(backendDir, 'package.json');
if (fs.existsSync(packagePath)) {
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    console.log('Dependencies:');
    Object.keys(packageJson.dependencies || {}).forEach(dep => {
        console.log(`   ✅ ${dep}`);
    });
    
    // Check if node_modules exists
    const nodeModulesPath = path.join(backendDir, 'node_modules');
    console.log(`\nnode_modules: ${fs.existsSync(nodeModulesPath) ? '✅' : '❌'}`);
    if (!fs.existsSync(nodeModulesPath)) {
        console.log('   ⚠️  Run "npm install" in backend folder');
    }
} else {
    console.log('❌ package.json not found!');
}

// Test Python packages
console.log('\n🔧 TESTING PYTHON PACKAGES:');
console.log('----------------------------------------');
exec('python -c "import nmap; import requests; import dns.resolver; print(\'✅ All Python packages imported successfully\')"', 
    (error, stdout, stderr) => {
        if (error) {
            console.log('❌ Python package import failed:');
            console.log(stderr);
        } else {
            console.log(stdout);
        }
        
        // Final summary
        console.log('\n📊 ==================================');
        console.log('📊 DIAGNOSTIC SUMMARY');
        console.log('📊 ==================================');
        
        console.log('\nTo fix CSS issues:');
        console.log('1. Make sure index.html has <style> tags with CSS');
        console.log('2. Or ensure style.css exists in public folder');
        console.log('3. Clear browser cache (Ctrl+Shift+Delete)');
        console.log('4. Use Incognito/Private mode to test');
        
        console.log('\nTo start the server:');
        console.log('1. cd backend');
        console.log('2. node app.js');
        console.log('3. Open http://localhost:3000\n');
    }
);