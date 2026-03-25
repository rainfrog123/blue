import React from 'react';
import {
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Typography,
  TextField,
  FormControlLabel,
  Switch,
  Grid
} from '@mui/material';
import { DatePicker } from '@mui/x-date-pickers';

const BookingForm = ({ formData, onChange, onNext, onBack, rates }) => {
  const handleDateChange = (field) => (date) => {
    console.log('Date change:', {
      field,
      date,
      isValid: date instanceof Date,
      value: date?.toString()
    });
    onChange(field, date);
  };

  const handleChange = (field) => (event) => {
    onChange(field, event.target.value);
  };

  const handleSwitchChange = (field) => (event) => {
    onChange(field, event.target.checked);
  };

  const getRoomTypes = () => {
    if (!rates || !formData.property) return [];
    return rates[formData.property].roomTypes || [];
  };

  const isExtension = formData.calculationType === 'extension';

  return (
    <Box sx={{ minHeight: 300, display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Typography variant="h6" gutterBottom>
        Booking Details
      </Typography>

      <Grid container spacing={3}>
        {isExtension && (
          <>
            <Grid item xs={12} md={6}>
              <DatePicker
                label="Original Check-in Date"
                value={formData.originalCheckIn}
                onChange={handleDateChange('originalCheckIn')}
                renderInput={(params) => <TextField {...params} fullWidth />}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <DatePicker
                label="Original Check-out Date"
                value={formData.originalCheckOut}
                onChange={handleDateChange('originalCheckOut')}
                renderInput={(params) => <TextField {...params} fullWidth />}
              />
            </Grid>
          </>
        )}

        <Grid item xs={12} md={6}>
          <DatePicker
            label={isExtension ? "New Check-out Date" : "Check-in Date"}
            value={isExtension ? formData.checkOut : formData.checkIn}
            onChange={handleDateChange(isExtension ? 'checkOut' : 'checkIn')}
            renderInput={(params) => <TextField {...params} fullWidth />}
          />
        </Grid>

        {!isExtension && (
          <Grid item xs={12} md={6}>
            <DatePicker
              label="Check-out Date"
              value={formData.checkOut}
              onChange={handleDateChange('checkOut')}
              renderInput={(params) => <TextField {...params} fullWidth />}
            />
          </Grid>
        )}

        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel id="capacity-label">Capacity</InputLabel>
            <Select
              labelId="capacity-label"
              value={formData.capacity}
              label="Capacity"
              onChange={handleChange('capacity')}
            >
              <MenuItem value="1">1 Person</MenuItem>
              <MenuItem value="2">2 Persons</MenuItem>
            </Select>
          </FormControl>
        </Grid>

        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel id="room-type-label">Room Type</InputLabel>
            <Select
              labelId="room-type-label"
              value={formData.roomType}
              label="Room Type"
              onChange={handleChange('roomType')}
            >
              {getRoomTypes().map((type) => (
                <MenuItem key={type} value={type}>{type}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>

        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="Extra Discount (%)"
            type="number"
            value={formData.extraDiscount}
            onChange={handleChange('extraDiscount')}
            inputProps={{ min: 0, max: 15 }}
          />
        </Grid>

        {!isExtension && (
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  checked={formData.hasRoomChange}
                  onChange={handleSwitchChange('hasRoomChange')}
                />
              }
              label="Add Room Type Change"
            />
          </Grid>
        )}

{isExtension && (
  <Grid item xs={12}>
    <FormControlLabel
      control={
        <Switch
          checked={formData.overrideSevenDayRule}
          onChange={handleSwitchChange('overrideSevenDayRule')}
        />
      }
      label="Disable Including Original Stay for Long-Stay Discount"
    />
  </Grid>
)}
      </Grid>

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
        <Button onClick={onBack}>
          Back
        </Button>
        <Button
          variant="contained"
          onClick={onNext}
          disabled={!formData.roomType || !formData.checkIn || !formData.checkOut}
        >
          Next
        </Button>
      </Box>
    </Box>
  );
};

export default BookingForm; 