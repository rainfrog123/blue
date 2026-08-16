import React from 'react';
import {
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Typography
} from '@mui/material';

const CalculationType = ({ formData, onChange, onNext, onBack }) => {
  const handleChange = (event) => {
    onChange('calculationType', event.target.value);
  };

  return (
    <Box sx={{ minHeight: 300, display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Typography variant="h6" gutterBottom>
        Select Calculation Type
      </Typography>

      <FormControl fullWidth>
        <InputLabel id="calculation-type-label">Calculation Type</InputLabel>
        <Select
          labelId="calculation-type-label"
          id="calculation-type"
          value={formData.calculationType}
          label="Calculation Type"
          onChange={handleChange}
        >
          <MenuItem value="new">New Booking</MenuItem>
          <MenuItem value="extension">Booking Extension</MenuItem>
          <MenuItem value="change">New Booking with Room Type Change</MenuItem>
        </Select>
      </FormControl>

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 'auto' }}>
        <Button onClick={onBack}>
          Back
        </Button>
        <Button
          variant="contained"
          onClick={onNext}
          disabled={!formData.calculationType}
        >
          Next
        </Button>
      </Box>
    </Box>
  );
};

export default CalculationType; 