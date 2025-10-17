// Use dynamic import for node-fetch
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

async function generateZohoRefreshToken() {
  // Replace with your actual credentials
  const clientId = process.env.ZOHO_CLIENT_ID || '1000.XXXXXXXXXXXX';
  const clientSecret = process.env.ZOHO_CLIENT_SECRET || 'XXXXXXXXXXXXXXXXXXXXXXXX';
  
  console.log('🚀 Starting Zoho Token Generation...');
  console.log('📝 Using Client ID:', clientId.substring(0, 10) + '...');
  
  const scope = 'ZohoMail.messages.CREATE';
  
  // Generate the self-client code
  const selfClientCode = `${clientId}:${clientSecret}:${scope}`;
  const base64Code = Buffer.from(selfClientCode).toString('base64');

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
      console.log('🔑 Access Token:', data.access_token ? 'Received' : 'Not received');
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
    return null;
  }
}

// Run the function
generateZohoRefreshToken().then(refreshToken => {
  if (!refreshToken) {
    console.log('\n❌ Failed to generate refresh token');
  }
});