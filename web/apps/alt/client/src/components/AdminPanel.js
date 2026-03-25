import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Button, 
  TextField, 
  Typography, 
  Paper,
  Alert,
  Snackbar
} from '@mui/material';
import { getRates, updateRates } from '../api/rates';

export default function AdminPanel({ onRatesUpdate }) {
  const [rates, setRates] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    loadRates();
  }, []);

  const loadRates = async () => {
    try {
      const currentRates = await getRates();
      setRates(JSON.stringify(currentRates, null, 2));
      if (onRatesUpdate) {
        onRatesUpdate(currentRates);
      }
    } catch (err) {
      setError('Failed to load rates');
    }
  };

  const handleSave = async () => {
    try {
      let parsedRates;
      try {
        parsedRates = JSON.parse(rates);
      } catch (err) {
        setError('Invalid JSON format');
        return;
      }

      await updateRates(parsedRates);
      if (onRatesUpdate) {
        onRatesUpdate(parsedRates);
      }
      setSuccess('Rates updated successfully');
      setError('');
    } catch (err) {
      setError('Failed to update rates');
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Paper sx={{ p: 3 }}>
        <Typography variant="h5" gutterBottom>
          Rate Management
        </Typography>
        
        <TextField
          fullWidth
          multiline
          rows={20}
          value={rates}
          onChange={(e) => setRates(e.target.value)}
          variant="outlined"
          sx={{ mb: 2, fontFamily: 'monospace' }}
        />

        <Button 
          variant="contained" 
          color="primary" 
          onClick={handleSave}
          sx={{ mr: 2 }}
        >
          Save Changes
        </Button>
        
        <Button 
          variant="outlined" 
          onClick={loadRates}
        >
          Reload Rates
        </Button>

        <Snackbar 
          open={!!error} 
          autoHideDuration={6000} 
          onClose={() => setError('')}
        >
          <Alert severity="error">{error}</Alert>
        </Snackbar>

        <Snackbar 
          open={!!success} 
          autoHideDuration={6000} 
          onClose={() => setSuccess('')}
        >
          <Alert severity="success">{success}</Alert>
        </Snackbar>
      </Paper>
    </Box>
  );
} 