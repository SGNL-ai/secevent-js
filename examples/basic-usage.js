#!/usr/bin/env node

/**
 * Basic Usage Examples for secevent-js
 * Demonstrates parsing and generating Security Event Tokens
 */

const readline = require('readline');
const { 
  createParser, 
  createBuilder, 
  Events, 
  SubjectIdentifiers
} = require('../dist');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      resolve(answer.trim());
    });
  });
}

/**
 * Example 1: Parse a Security Event Token
 */
async function parseEventExample() {
  console.log('\n' + '='.repeat(60));
  console.log('Example 1: Parse a Security Event Token');
  console.log('='.repeat(60) + '\n');
  
  console.log('Enter a JWT token to parse (or press Enter to use sample token):');
  let jwt = await question('> ');
  
  if (!jwt) {
    // Sample token from CAEP.dev
    jwt = 'eyJhbGciOiJub25lIn0.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXZlbnRzIjp7Imh0dHBzOi8vc2NoZW1hcy5vcGVuaWQubmV0L3NlY2V2ZW50L2NhZXAvZXZlbnQtdHlwZS9zZXNzaW9uLXJldm9rZWQiOnsiZXZlbnRfdGltZXN0YW1wIjoxNzA0MDY3MjAwLCJzdWJqZWN0Ijp7ImZvcm1hdCI6ImVtYWlsIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn19fSwiaWF0IjoxNzA0MDY3MjAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImp0aSI6InNhbXBsZS1qdGktMTIzNDUifQ.';
    console.log('\nUsing sample token...\n');
  }
  
  const parser = createParser();
  
  try {
    // Decode without verification (for demonstration)
    const decoded = parser.decode(jwt);
    
    console.log('Successfully parsed token!\n');
    console.log('Token Details:');
    console.log('-'.repeat(40));
    console.log(`Issuer:    ${decoded.iss}`);
    console.log(`Audience:  ${decoded.aud}`);
    console.log(`JTI:       ${decoded.jti}`);
    console.log(`Issued At: ${new Date(decoded.iat * 1000).toISOString()}`);
    
    // Extract event information
    const eventTypes = parser.getEventTypes(decoded);
    console.log(`\nEvent Types: ${eventTypes.length} event(s) found`);
    
    eventTypes.forEach((eventType, index) => {
      console.log(`\nEvent ${index + 1}: ${eventType.split('/').pop()}`);
      
      const event = parser.extractEvent(decoded, eventType);
      if (event) {
        if (event.event_timestamp) {
          console.log(`  Timestamp: ${new Date(event.event_timestamp * 1000).toISOString()}`);
        }
        if (event.subject) {
          console.log(`  Subject Format: ${event.subject.format}`);
          if (event.subject.email) {
            console.log(`  Email: ${event.subject.email}`);
          }
          if (event.subject.id) {
            console.log(`  ID: ${event.subject.id}`);
          }
        }
      }
    });
    
    console.log('\nFull Decoded Payload:');
    console.log(JSON.stringify(decoded, null, 2));
    
  } catch (error) {
    console.error('Error parsing token:', error.message);
  }
}

/**
 * Example 2: Generate a Security Event Token
 */
async function generateEventExample() {
  console.log('\n' + '='.repeat(60));
  console.log('Example 2: Generate a Security Event Token');
  console.log('='.repeat(60) + '\n');
  
  console.log('Let\'s create a Security Event Token!\n');
  
  // Get user inputs
  const issuer = await question('Issuer URL (e.g., https://issuer.example.com): ') || 'https://issuer.example.com';
  const audience = await question('Audience URL (e.g., https://app.example.com): ') || 'https://app.example.com';
  
  console.log('\nSelect event type:');
  console.log('1. Session Revoked');
  console.log('2. Credential Change');
  console.log('3. Token Claims Change');
  const eventChoice = await question('Choice (1-3): ') || '1';
  
  console.log('\nSubject identifier:');
  const subjectEmail = await question('Email address: ') || 'user@example.com';
  
  // Create the builder
  const builder = createBuilder();
  
  // Create subject identifier
  const subject = SubjectIdentifiers.email(subjectEmail);
  
  // Create event based on choice
  let event;
  const timestamp = Math.floor(Date.now() / 1000);
  
  switch (eventChoice) {
    case '2':
      event = Events.credentialChange(subject, timestamp, {
        credential_type: 'password',
        change_type: 'update'
      });
      break;
    case '3':
      event = Events.tokenClaimsChange(subject, timestamp, {
        claims: { role: 'admin' }
      });
      break;
    default:
      event = Events.sessionRevoked(subject, timestamp, 'User requested logout');
      break;
  }
  
  // Build the payload
  const payload = builder
    .withIssuer(issuer)
    .withAudience(audience)
    .withEvent(event)
    .buildPayload();
  
  console.log('\nGenerated SET Payload:');
  console.log(JSON.stringify(payload, null, 2));
  
  // Create unsigned JWT (for demonstration)
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const unsignedJwt = `${header}.${body}.`;
  
  console.log('\nUnsigned JWT (for testing):');
  console.log(unsignedJwt);
  
  console.log('\nNote: In production, you would sign this token with a private key.');
  console.log('Example signing code:');
  console.log(`
    const signingKey = {
      alg: 'RS256',
      key: privateKey // Your private key
    };
    
    const signedToken = await builder
      .withIssuer(issuer)
      .withAudience(audience)
      .withEvent(event)
      .sign(signingKey);
  `);
}

/**
 * Main menu
 */
async function main() {
  console.log('\nSecurity Event Token (SET) Examples');
  console.log('Using the @sgnl/secevent library\n');
  
  let running = true;
  
  while (running) {
    console.log('\nSelect an example:');
    console.log('1. Parse a Security Event Token');
    console.log('2. Generate a Security Event Token');
    console.log('3. Exit');
    
    const choice = await question('\nYour choice (1-3): ');
    
    switch (choice) {
      case '1':
        await parseEventExample();
        break;
      case '2':
        await generateEventExample();
        break;
      case '3':
      case 'exit':
      case 'quit':
        running = false;
        break;
      default:
        console.log('Invalid choice. Please select 1, 2, or 3.');
    }
  }
  
  rl.close();
  console.log('\nGoodbye!');
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}