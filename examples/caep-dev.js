#!/usr/bin/env node

/**
 * CAEP.dev SSF Stream Client
 * Interacts with CAEP.dev's Shared Signals Framework APIs
 * Tests our secevent-js library with real SSF streams
 */

const https = require('https');
const readline = require('readline');
const { createParser, createBuilder, Events, CAEP_EVENT_TYPES } = require('../dist');

const CAEP_DEV_BASE_URL = 'ssf.caep.dev';

// Helper to get token from environment or prompt user
async function getToken() {
  if (process.env.CAEP_DEV_TOKEN) {
    return process.env.CAEP_DEV_TOKEN;
  }
  
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  return new Promise((resolve) => {
    console.log('\nNo CAEP_DEV_TOKEN environment variable found.');
    console.log('Please enter your CAEP.dev bearer token:');
    console.log('(Get it from https://caep.dev - see README for instructions)\n');
    rl.question('Token: ', (token) => {
      rl.close();
      resolve(token.trim());
    });
  });
}

class CaepDevClient {
  constructor(token) {
    this.token = token;
    this.parser = createParser();
  }

  /**
   * Make an HTTPS request to CAEP.dev
   */
  async request(method, path, body = null) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: CAEP_DEV_BASE_URL,
        path: path,
        method: method,
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const result = data ? JSON.parse(data) : {};
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve({ status: res.statusCode, data: result });
            } else {
              reject(new Error(`HTTP ${res.statusCode}: ${JSON.stringify(result)}`));
            }
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
      
      if (body) {
        req.write(JSON.stringify(body));
      }
      
      req.end();
    });
  }

  /**
   * Create a new stream for receiving events
   */
  async createStream(deliveryMethod = 'poll') {
    console.log(`Creating ${deliveryMethod} stream on CAEP.dev...`);
    
    const streamConfig = {
      delivery: {
        method: deliveryMethod
      },
      events_requested: [
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
        'https://schemas.openid.net/secevent/caep/event-type/credential-change'
      ],
      format: 'json'
    };

    if (deliveryMethod === 'push') {
      // For testing, use a webhook.site endpoint or ngrok
      streamConfig.delivery.endpoint_url = process.env.WEBHOOK_URL || 'https://webhook.site/your-unique-url';
    }

    try {
      const response = await this.request('POST', '/ssf/streams', streamConfig);
      console.log('Stream created successfully!');
      console.log('Stream ID:', response.data.stream_id);
      console.log('Stream Config:', JSON.stringify(response.data, null, 2));
      return response.data;
    } catch (error) {
      console.error('Failed to create stream:', error.message);
      throw error;
    }
  }

  /**
   * Get stream status
   */
  async getStreamStatus(streamId) {
    console.log(`Getting status for stream ${streamId}...`);
    
    try {
      const response = await this.request('GET', `/ssf/status?stream_id=${streamId}`);
      console.log('Stream Status:', JSON.stringify(response.data, null, 2));
      return response.data;
    } catch (error) {
      console.error('Failed to get stream status:', error.message);
      throw error;
    }
  }

  /**
   * Add a subject to the stream
   */
  async addSubject(streamId, subject) {
    console.log(`Adding subject to stream ${streamId}...`);
    
    const subjectData = {
      stream_id: streamId,
      subject,
      verified: true
    };

    try {
      const response = await this.request('POST', '/ssf/subjects:add', subjectData);
      console.log('Subject added successfully!');
      return response.data;
    } catch (error) {
      console.error('Failed to add subject:', error.message);
      throw error;
    }
  }

  /**
   * Poll for events from the stream
   */
  async pollEvents(streamId) {
    console.log(`Polling for events from stream ${streamId}...`);
    
    // Try with stream_id in body and Postman parameters
    const pollRequest = {
      stream_id: streamId,
      ack: [],
      maxEvents: 10,
      returnImmediately: true
    };

    console.log('Poll request:', JSON.stringify(pollRequest, null, 2));

    try {
      const response = await this.request('POST', '/ssf/streams/poll', pollRequest);
      
      if (response.data.sets && Object.keys(response.data.sets).length > 0) {
        const eventCount = Object.keys(response.data.sets).length;
        console.log(`Received ${eventCount} events!\n`);
        
        // Parse each SET using our library
        let eventIndex = 1;
        for (const setToken of Object.values(response.data.sets)) {
          console.log(`\n${'='.repeat(60)}`);
          console.log(`Security Event Token #${eventIndex}`);
          console.log(`${'='.repeat(60)}`);
          
          try {
            const decoded = this.parser.decode(setToken);
            
            // Use library methods to extract information
            console.log('\nParsed with secevent-js library:');
            console.log(`  • Event Types: ${this.parser.getEventTypes(decoded).join(', ')}`);
            console.log(`  • Has Session Revoked: ${this.parser.hasEvent(decoded, CAEP_EVENT_TYPES.SESSION_REVOKED)}`);
            console.log(`  • JTI: ${decoded.jti}`);
            console.log(`  • Issuer: ${decoded.iss}`);
            console.log(`  • Audience: ${decoded.aud}`);
            console.log(`  • Issued At: ${new Date(decoded.iat * 1000).toISOString()}`);
            
            // Extract events using library method
            const sessionRevoked = this.parser.extractEvent(decoded, CAEP_EVENT_TYPES.SESSION_REVOKED);
            
            if (sessionRevoked) {
              console.log('\nEvent Details (extracted via library):');
              console.log(`  • Event Timestamp: ${new Date(sessionRevoked.event_timestamp * 1000).toISOString()}`);
              if (sessionRevoked.subject) {
                console.log(`  • Subject Format: ${sessionRevoked.subject.format}`);
                if (sessionRevoked.subject.email) {
                  console.log(`  • Subject Email: ${sessionRevoked.subject.email}`);
                }
                if (sessionRevoked.subject.id) {
                  console.log(`  • Subject ID: ${sessionRevoked.subject.id}`);
                }
              }
              if (sessionRevoked.reason) {
                console.log(`  • Reason: ${sessionRevoked.reason}`);
              }
            }
            
            // Pretty print the full JSON payload
            console.log('\nFull JWT Payload (JSON):');
            console.log(JSON.stringify(decoded, null, 2));
            
            eventIndex++;
          } catch (parseError) {
            console.error('Failed to parse SET:', parseError.message);
          }
        }
      } else {
        console.log('No events available');
      }
      
      return response.data;
    } catch (error) {
      console.error('Failed to poll events:', error.message);
      throw error;
    }
  }

  /**
   * Verify stream configuration
   */
  async verifyStream(streamId) {
    console.log(`Sending verification event for stream ${streamId}...`);
    
    const builder = createBuilder();
    const verificationEvent = Events.verification();
    
    // Note: This would need proper signing configuration
    const payload = builder
      .withIssuer('https://test.example.com')
      .withAudience('https://ssf.caep.dev')
      .withEvent(verificationEvent)
      .buildPayload();

    console.log('Verification payload:', JSON.stringify(payload, null, 2));
    
    // The actual verification endpoint would need to be confirmed
    console.log('Note: Actual verification requires proper endpoint and signing configuration');
    
    return payload;
  }

  /**
   * Delete a stream
   */
  async deleteStream(streamId) {
    console.log(`Deleting stream ${streamId}...`);
    
    try {
      const response = await this.request('DELETE', `/ssf/streams/${streamId}`);
      console.log('Stream deleted successfully!');
      return response.data;
    } catch (error) {
      console.error('Failed to delete stream:', error.message);
      throw error;
    }
  }

  /**
   * Get or create a properly configured stream
   */
  async getOrCreateStream() {
    console.log('Checking for existing streams...');
    
    try {
      // First, try to get existing streams
      const response = await this.request('GET', '/ssf/streams');
      
      if (response.data && response.data.length > 0) {
        const stream = response.data[0];
        console.log(`Found existing stream: ${stream.stream_id}`);
        
        // Check if it's configured for polling
        if (stream.delivery && stream.delivery.method === 'urn:ietf:rfc:8936') {
          console.log('Stream is already configured for polling.');
          return stream;
        } else {
          console.log('Stream is configured for push delivery, updating to poll...');
          // Update to polling
          const updateData = {
            stream_id: stream.stream_id,
            delivery: {
              method: 'urn:ietf:rfc:8936' // Poll method
            }
          };
          const updated = await this.request('PATCH', '/ssf/streams', updateData);
          console.log('Stream updated to polling mode.');
          return updated.data;
        }
      }
    } catch {
      // No existing stream or error getting it
      console.log('No existing stream found.');
    }
    
    // Create a new stream with random audience
    console.log('Creating new stream...');
    const randomAudience = `https://example-${Math.random().toString(36).substring(7)}.com`;
    const streamConfig = {
      delivery: {
        method: 'urn:ietf:rfc:8936' // Poll method
      },
      aud: randomAudience,
      events_requested: [
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
        'https://schemas.openid.net/secevent/caep/event-type/credential-change'
      ],
      format: 'json'
    };
    
    const response = await this.request('POST', '/ssf/streams', streamConfig);
    console.log('Stream created successfully!');
    console.log(`Stream ID: ${response.data.stream_id}`);
    console.log(`Audience: ${response.data.aud || randomAudience}`);
    return response.data;
  }
}

async function main() {
  console.log('CAEP.dev SSF Stream Client\n');
  console.log('This tool demonstrates Security Event Token interoperability with CAEP.dev\n');
  
  try {
    // Get token
    const token = await getToken();
    
    if (!token || token === 'your-bearer-token-here') {
      console.error('\nError: Invalid token provided.');
      console.log('Please get your token from https://caep.dev');
      process.exit(1);
    }
    
    const client = new CaepDevClient(token);
    
    // Get or create a stream
    const stream = await client.getOrCreateStream();
    
    // Poll for events
    console.log('\nPolling for events...');
    const pollResult = await client.pollEvents(stream.stream_id);
    
    // Check if we got any events
    if (!pollResult.sets || Object.keys(pollResult.sets).length === 0) {
      console.log('\n' + '='.repeat(60));
      console.log('No events found in the stream.');
      console.log('='.repeat(60));
      console.log('\nTo generate test events:');
      console.log('1. Go to https://caep.dev');
      console.log('2. Navigate to the "Events" section');
      console.log('3. Create some test events (e.g., Session Revoked)');
      console.log('4. Run this script again to retrieve them\n');
    }
    
  } catch (error) {
    console.error('\nError:', error.message);
    if (error.message.includes('401') || error.message.includes('403')) {
      console.log('\nAuthentication failed. Your token may be expired.');
      console.log('Please get a new token from https://caep.dev');
    }
    process.exit(1);
  }
}

// Run the main function if executed directly
if (require.main === module) {
  main();
}