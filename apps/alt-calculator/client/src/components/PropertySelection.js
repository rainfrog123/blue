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

const PropertySelection = ({ formData, onChange, onNext }) => {
  const handleChange = (event) => {
    onChange('property', event.target.value);
  };

  const handleNext = () => {
    if (formData.property) {
      onNext();
    }
  };

  return (
    <Box sx={{ minHeight: 300, display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Typography variant="h6" gutterBottom>
        Select Property
      </Typography>

      <FormControl fullWidth>
        <InputLabel id="property-select-label">Property</InputLabel>
        <Select
          labelId="property-select-label"
          id="property-select"
          value={formData.property}
          label="Property"
          onChange={handleChange}
        >
          <MenuItem value="Alt_CM">Alt Chiang Mai</MenuItem>
          <MenuItem value="Alt_PR">Alt Ping River</MenuItem>
        </Select>
      </FormControl>

      <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 'auto' }}>
        <Button
          variant="contained"
          onClick={handleNext}
          disabled={!formData.property}
        >
          Next
        </Button>
      </Box>
    </Box>
  );
};

export default PropertySelection; 