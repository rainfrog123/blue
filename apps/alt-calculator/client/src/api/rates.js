import { RATES_DATA } from '../constants/rates';

// Load credentials from environment variables (set during build)
// For local development, create a .env file with REACT_APP_UPSTASH_URL and REACT_APP_UPSTASH_TOKEN
const UPSTASH_URL = process.env.REACT_APP_UPSTASH_URL || 'https://charmed-mammoth-17027.upstash.io';
const UPSTASH_TOKEN = process.env.REACT_APP_UPSTASH_TOKEN || 'SET_UPSTASH_TOKEN_IN_ENV';
export const RATES_KEY = 'rates_data';

async function upstashRest(command, value = null) {
  if (command === 'get') {
    const response = await fetch(`${UPSTASH_URL}/get/${RATES_KEY}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${UPSTASH_TOKEN}`,
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data.result;
  } else if (command === 'set') {
    const response = await fetch(`${UPSTASH_URL}/set/${RATES_KEY}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${UPSTASH_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(value),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data.result;
  }
}

export async function getRates() {
  try {
    const rates = await upstashRest('get');
    if (!rates) {
      console.log('No rates found in Redis, using static data');
      return RATES_DATA;
    }
    
    // Parse the rates if they're stored as a string
    let parsedRates;
    try {
      parsedRates = typeof rates === 'string' ? JSON.parse(rates) : rates;
      
      // Validate the data structure
      if (!parsedRates.Alt_CM || !parsedRates.Alt_PR || 
          !parsedRates.Alt_CM.roomTypes || !parsedRates.Alt_PR.roomTypes) {
        console.log('Invalid rates data structure, using static data');
        return RATES_DATA;
      }
      
      console.log('Successfully loaded rates from Redis');
      return parsedRates;
    } catch (parseError) {
      console.error('Error parsing rates:', parseError);
      return RATES_DATA;
    }
  } catch (error) {
    console.error('Error fetching rates:', error);
    console.log('Falling back to static data');
    return RATES_DATA;
  }
}

export async function updateRates(newRates) {
  try {
    // Validate the data structure before saving
    if (!newRates.Alt_CM || !newRates.Alt_PR || 
        !newRates.Alt_CM.roomTypes || !newRates.Alt_PR.roomTypes) {
      throw new Error('Invalid rates data structure');
    }
    
    await upstashRest('set', newRates);
    console.log('Successfully updated rates in Redis');
    return true;
  } catch (error) {
    console.error('Error updating rates:', error);
    return false;
  }
}

export async function initializeRates(initialRates) {
  try {
    const existingRates = await getRates();
    if (existingRates === RATES_DATA) {
      console.log('Initializing Redis with default rates');
      await updateRates(initialRates);
      return await getRates();
    }
    return existingRates;
  } catch (error) {
    console.error('Error initializing rates:', error);
    return RATES_DATA;
  }
}