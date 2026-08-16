import React, { useState } from 'react';
import {
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Typography,
  TextField,
  Grid,
  IconButton
} from '@mui/material';
import { DatePicker } from '@mui/x-date-pickers';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';

const RoomTypeChange = ({ formData, onChange, onNext, onBack, rates }) => {
  const [numChanges, setNumChanges] = useState(1);

  const handleDateChange = (index) => (date) => {
    const newChanges = [...formData.roomChanges];
    newChanges[index] = {
      ...newChanges[index] || {},
      date
    };
    onChange('roomChanges', newChanges);
  };

  const handleRoomTypeChange = (index) => (event) => {
    const newChanges = [...formData.roomChanges];
    newChanges[index] = {
      ...newChanges[index] || {},
      roomType: event.target.value
    };
    onChange('roomChanges', newChanges);
  };

  const handleCapacityChange = (index) => (event) => {
    const newChanges = [...formData.roomChanges];
    newChanges[index] = {
      ...newChanges[index] || {},
      capacity: event.target.value
    };
    onChange('roomChanges', newChanges);
  };

  const handleDiscountChange = (index) => (event) => {
    const newChanges = [...formData.roomChanges];
    newChanges[index] = {
      ...newChanges[index] || {},
      extraDiscount: event.target.value
    };
    onChange('roomChanges', newChanges);
  };

  const addChange = () => {
    if (numChanges < 3) {
      setNumChanges(prev => prev + 1);
    }
  };

  const removeChange = (index) => {
    const newChanges = formData.roomChanges.filter((_, i) => i !== index);
    onChange('roomChanges', newChanges);
    setNumChanges(prev => prev - 1);
  };

  const getRoomTypes = () => {
    if (!rates || !formData.property) return [];
    return rates[formData.property].roomTypes || [];
  };

  const renderRoomChange = (index) => (
    <Grid container spacing={3} key={index} sx={{ mb: 3 }}>
      <Grid item xs={12}>
        <Typography variant="subtitle1" gutterBottom>
          Room Change {index + 1}
          {index > 0 && (
            <IconButton
              color="error"
              onClick={() => removeChange(index)}
              sx={{ ml: 2 }}
            >
              <DeleteIcon />
            </IconButton>
          )}
        </Typography>
      </Grid>

      <Grid item xs={12} md={6}>
        <DatePicker
          label="Date of Room Change"
          value={formData.roomChanges[index]?.date || null}
          onChange={handleDateChange(index)}
          renderInput={(params) => <TextField {...params} fullWidth />}
          minDate={formData.checkIn}
          maxDate={formData.checkOut}
        />
      </Grid>

      <Grid item xs={12} md={6}>
        <FormControl fullWidth>
          <InputLabel>New Room Type</InputLabel>
          <Select
            value={formData.roomChanges[index]?.roomType || ''}
            onChange={handleRoomTypeChange(index)}
            label="New Room Type"
          >
            {getRoomTypes().map((type) => (
              <MenuItem key={type} value={type}>{type}</MenuItem>
            ))}
          </Select>
        </FormControl>
      </Grid>

      <Grid item xs={12} md={6}>
        <FormControl fullWidth>
          <InputLabel>New Capacity</InputLabel>
          <Select
            value={formData.roomChanges[index]?.capacity || '1'}
            onChange={handleCapacityChange(index)}
            label="New Capacity"
          >
            <MenuItem value="1">1 Person</MenuItem>
            <MenuItem value="2">2 Persons</MenuItem>
          </Select>
        </FormControl>
      </Grid>

      <Grid item xs={12} md={6}>
        <TextField
          fullWidth
          label="Extra Discount (%)"
          type="number"
          value={formData.roomChanges[index]?.extraDiscount || 0}
          onChange={handleDiscountChange(index)}
          inputProps={{ min: 0, max: 15 }}
        />
      </Grid>
    </Grid>
  );

  return (
    <Box sx={{ minHeight: 300, display: 'flex', flexDirection: 'column' }}>
      <Typography variant="h6" gutterBottom>
        Room Type Changes
      </Typography>

      {Array.from({ length: numChanges }).map((_, index) => renderRoomChange(index))}

      {numChanges < 3 && (
        <Button
          startIcon={<AddIcon />}
          onClick={addChange}
          sx={{ alignSelf: 'flex-start', mb: 3 }}
        >
          Add Room Change
        </Button>
      )}

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 'auto' }}>
        <Button onClick={onBack}>
          Back
        </Button>
        <Button
          variant="contained"
          onClick={onNext}
          disabled={formData.roomChanges.length === 0 || 
                   formData.roomChanges.some(change => !change?.date || !change?.roomType)}
        >
          Next
        </Button>
      </Box>
    </Box>
  );
};

export default RoomTypeChange; 