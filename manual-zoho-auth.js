const axios = require('axios');
const readline = require('readline');
const qs = require('querystring');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function manualZohoAuth() {
  console.log('🔗 Zoho Manual OAuth Token Generation\n');
  
  // Replace with your actual credentials
  const clientId = 'x'; // Your actual Client ID
  const clientSecret = 'x'; // Your actual Client Secret
  
  console.log('📝 Using:');
  console.log('   Client ID:', clientId);
  console.log('   Client Secret:', clientSecret.substring(0, 4) + '...' + clientSecret.substring(clientSecret.length - 4));
  
  // Step 1: Generate authorization URL
  const authUrl = `https://accounts.zoho.com/oauth/v2/auth?` +
    `scope=ZohoMail.messages.CREATE&` +
    `client_id=${clientId}&` +
    `response_type=code&` +
    `redirect_uri=https://www.zoho.com&` +
    `access_type=offline`;
  
  console.log('\n📋 STEP 1: Open this URL in your browser:');
  console.log(authUrl);
  console.log('\n📋 STEP 2: Authorize the application');
  console.log('   - You may need to log in to your Zoho account');
  console.log('   - Click "Accept" to grant permissions');
  console.log('   - You will be redirected to a URL that looks like:');
  console.log('     https://www.zoho.com/?code=1000.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&location=us');
  console.log('\n📋 STEP 3: Copy the "code" parameter from the URL');
  
  const authCode = await question('\n🔑 Paste the authorization code here: ');
  
  try {
    console.log('\n🔄 Exchanging authorization code for tokens...');
    
    const response = await axios.post('https://accounts.zoho.com/oauth/v2/token', 
      qs.stringify({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        code: authCode,
        redirect_uri: 'https://www.zoho.com'
      }), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        }
      }
    );

    const data = response.data;
    
    console.log('\n✅ SUCCESS! Tokens received:');
    console.log('🔄 Refresh Token:', data.refresh_token);
    console.log('🔑 Access Token:', data.access_token ? data.access_token.substring(0, 20) + '...' : 'Not received');
    console.log('⏰ Expires In:', data.expires_in, 'seconds');
    
    console.log('\n📋 ADD THIS TO YOUR RAILWAY ENVIRONMENT VARIABLES:');
    console.log('ZOHO_REFRESH_TOKEN=' + data.refresh_token);
    console.log('\n💡 Also add these:');
    console.log('ZOHO_CLIENT_ID=' + clientId);
    console.log('ZOHO_CLIENT_SECRET=' + clientSecret);
    
  } catch (error) {
    console.error('\n❌ Error exchanging code:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
  
  rl.close();
}

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

manualZohoAuth();