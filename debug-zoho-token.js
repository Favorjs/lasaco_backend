const fetch = require('node-fetch');

console.log('🚀 Starting Zoho Token Generation...');

async function generateZohoRefreshToken() {
  // Replace these with your actual credentials
  const clientId = process.env.ZOHO_CLIENT_ID || '1000.XXXXXXXXXXXX';
  const clientSecret = process.env.ZOHO_CLIENT_SECRET || 'XXXXXXXXXXXXXXXXXXXXXXXX';
  
  console.log('📝 Using Client ID:', clientId.substring(0, 10) + '...');
  console.log('📝 Using Client Secret:', clientSecret.substring(0, 10) + '...');
  
  const scope = 'ZohoMail.messages.CREATE';
  
  // Generate the self-client code
  const selfClientCode = `${clientId}:${clientSecret}:${scope}`;
  console.log('🔑 Self Client Code (first 50 chars):', selfClientCode.substring(0, 50) + '...');
  
  const base64Code = Buffer.from(selfClientCode).toString('base64');
  console.log('🔐 Base64 Code (first 50 chars):', base64Code.substring(0, 50) + '...');

  try {
    console.log('📤 Making request to Zoho...');
    
    const response = await fetch('https://accounts.zoho.com/oauth/v2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        code: base64Code,
        scope: scope
      })
    });

    console.log('📥 Response Status:', response.status);
    console.log('📥 Response OK:', response.ok);

    const data = await response.json();
    console.log('📄 Full Response:', JSON.stringify(data, null, 2));
    
    if (data.error) {
      console.error('❌ Zoho API Error:', data.error);
      console.error('❌ Error Description:', data.error_description);
      return null;
    }

    if (data.refresh_token) {
      console.log('\n🎉 SUCCESS! Tokens Generated:');
      console.log('🔄 Refresh Token:', data.refresh_token);
      console.log('🔑 Access Token:', data.access_token);
      console.log('⏰ Expires In:', data.expires_in, 'seconds');
      
      console.log('\n📋 ADD THIS TO YOUR RAILWAY ENVIRONMENT VARIABLES:');
      console.log('ZOHO_REFRESH_TOKEN=' + data.refresh_token);
      
      return data.refresh_token;
    } else {
      console.log('❌ No refresh token in response');
      return null;
    }
  } catch (error) {
    console.error('💥 Fetch Error:', error.message);
    console.error('💥 Stack:', error.stack);
    return null;
  }
}

// Run the function
generateZohoRefreshToken().then(refreshToken => {
  if (!refreshToken) {
    console.log('\n❌ Failed to generate refresh token');
    console.log('\n💡 Troubleshooting tips:');
    console.log('1. Check your Client ID and Client Secret');
    console.log('2. Make sure your Zoho app has ZohoMail scope');
    console.log('3. Try the manual method below');
  }
  process.exit(0);
});