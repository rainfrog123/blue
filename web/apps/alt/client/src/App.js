import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  ThemeProvider,
  createTheme,
  CssBaseline,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Button,
  Divider,
  IconButton,
  Link,
  Dialog,
} from '@mui/material';
import { LocalizationProvider, DatePicker } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { differenceInDays, startOfToday, addDays } from 'date-fns';
import Summary from './components/Summary';
import { getRates, initializeRates } from './api/rates';
import { RATES_DATA } from './constants/rates';
import DeleteIcon from '@mui/icons-material/Delete';
import AdminPanel from './components/AdminPanel';

const theme = createTheme({
  palette: {
    primary: {
      main: '#007AFF', // Apple blue
    },
    background: {
      default: '#f5f5f7', // Apple light gray
      paper: '#ffffff',
    },
    text: {
      primary: '#1d1d1f', // Apple dark gray
    }
  },
  typography: {
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
    h4: {
      fontSize: '1.5rem',
      fontWeight: 500,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 500,
      color: '#1d1d1f',
    },
    subtitle1: {
      fontSize: '0.875rem',
      fontWeight: 500,
    },
    body1: {
      fontSize: '0.875rem',
    },
    body2: {
      fontSize: '0.8125rem',
    },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          padding: '24px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
          borderRadius: '12px',
        },
      },
    },
    MuiSelect: {
      styleOverrides: {
        root: {
          backgroundColor: 'white',
          borderRadius: '8px',
          '& fieldset': {
            borderColor: '#e1e1e6',
          },
          '&:hover fieldset': {
            borderColor: '#b8b8bf !important',
          },
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          backgroundColor: 'white',
          borderRadius: '8px',
          '& fieldset': {
            borderColor: '#e1e1e6',
          },
          '&:hover fieldset': {
            borderColor: '#b8b8bf !important',
          },
        },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: {
          fontSize: '0.8125rem',
          color: '#86868b',
          '&.Mui-focused': {
            color: '#007AFF',
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
          textTransform: 'none',
          fontWeight: 500,
          fontSize: '0.9375rem',
          padding: '8px 16px',
          boxShadow: 'none',
          '&:hover': {
            boxShadow: 'none',
          },
        },
        outlined: {
          borderColor: '#e1e1e6',
          color: '#1d1d1f',
          '&:hover': {
            borderColor: '#b8b8bf',
            backgroundColor: 'rgba(0,0,0,0.02)',
          },
        },
        contained: {
          backgroundColor: '#007AFF',
          '&:hover': {
            backgroundColor: '#0066d9',
          },
        },
      },
    },
    MuiDivider: {
      styleOverrides: {
        root: {
          margin: '24px 0',
          borderColor: '#e1e1e6',
        },
      },
    },
  },
});

const BusinessCardDialog = ({ open, onClose }) => (
  <Dialog 
    open={open} 
    onClose={onClose}
    maxWidth="xs"
    PaperProps={{
      sx: {
        backgroundColor: 'transparent',
        boxShadow: 'none',
        overflow: 'hidden',
        p: 0,
      }
    }}
  >
    <Box
      component="img"
      src="/business-card.jpg"
      alt="Jeffrey's Business Card"
      sx={{
        width: '100%',
        maxWidth: '200px',
        height: 'auto',
        display: 'block',
        borderRadius: '8px',
        margin: '0 auto',
      }}
    />
  </Dialog>
);

function App() {
  const [roomPeriods, setRoomPeriods] = useState([
    {
      id: 1,
      roomType: 'Ensuite Single',
      capacity: '1',
      checkIn: startOfToday(),
      checkOut: addDays(startOfToday(), 7),
      season: 'High',
    }
  ]);
  const [formData, setFormData] = useState({
    property: 'Alt_CM',
    extraDiscount: 0,
    checkIn: null,
    checkOut: null,
    hasRoomChange: false
  });
  const [calculation, setCalculation] = useState(null);
  const [rates, setRates] = useState(RATES_DATA);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [businessCardOpen, setBusinessCardOpen] = useState(false);
  const [thaiTime, setThaiTime] = useState(new Date().toLocaleTimeString('en-US', {
    timeZone: 'Asia/Bangkok',
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }));
  const [weather, setWeather] = useState(null);

  const handleRatesUpdate = (newRates) => {
    console.log('Updating rates in App:', newRates);
    setRates(newRates);
  };

  useEffect(() => {
    const loadRates = async () => {
      try {
        setLoading(true);
        const loadedRates = await initializeRates(RATES_DATA);
        setRates(loadedRates);
        setError(null);
      } catch (err) {
        console.error('Failed to load rates:', err);
        setError('Failed to load rates. Using default rates.');
        setRates(RATES_DATA);
      } finally {
        setLoading(false);
      }
    };

    loadRates();
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      setThaiTime(new Date().toLocaleTimeString('en-US', {
        timeZone: 'Asia/Bangkok',
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }));
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const fetchWeather = async () => {
      try {
        // Simulating weather data until we have an API key
        setWeather({
          main: {
            temp: 28,
          },
          weather: [
            {
              description: "sunny"
            }
          ]
        });
      } catch (error) {
        console.error('Error fetching weather:', error);
      }
    };

    fetchWeather();
    const interval = setInterval(fetchWeather, 300000); // Update every 5 minutes

    return () => clearInterval(interval);
  }, []);

  const handleChange = (field) => (event) => {
    setFormData(prev => ({
      ...prev,
      [field]: event.target.value
    }));
  };

  const handleRoomPeriodChange = (index, field, value) => {
    setRoomPeriods(prev => {
      const newPeriods = [...prev];
      newPeriods[index] = {
        ...newPeriods[index],
        [field]: value
      };

      // If this is a check-in date change, update the checkout date to 7 days later
      if (field === 'checkIn' && value) {
        newPeriods[index] = {
          ...newPeriods[index],
          checkOut: addDays(value, 7)
        };
      }

      // If this is a check-out date change, update the next period's check-in date
      if (field === 'checkOut' && index < newPeriods.length - 1) {
        newPeriods[index + 1] = {
          ...newPeriods[index + 1],
          checkIn: value
        };
      }

      return newPeriods;
    });
  };

  const addRoomPeriod = () => {
    const lastPeriod = roomPeriods[roomPeriods.length - 1];
    const newCheckIn = lastPeriod?.checkOut || startOfToday();
    
    setRoomPeriods(prev => [
      ...prev,
      {
        id: prev.length + 1,
        roomType: lastPeriod?.roomType || 'Ensuite Single',
        capacity: '1',
        checkIn: newCheckIn,
        checkOut: addDays(newCheckIn, 7),
        season: lastPeriod?.season || 'High',
      }
    ]);
  };

  const getRoomTypes = () => {
    return rates[formData.property]?.roomTypes || [];
  };

  const getLongStayDiscount = (totalNights) => {
    if (totalNights >= 29) return 0.50;
    if (totalNights >= 19) return 0.35;
    if (totalNights >= 9) return 0.20;
    return 0;
  };

  const calculateTotal = () => {
    if (!rates[formData.property]) {
      setError('Property rates not found');
      return;
    }

    if (roomPeriods.some(p => !p.roomType || !p.checkIn || !p.checkOut || !p.capacity || !p.season)) {
      alert('Please fill in all room period details');
      return;
    }

    const totalNights = roomPeriods.reduce((sum, period) => {
      const nights = differenceInDays(new Date(period.checkOut), new Date(period.checkIn));
      return sum + nights;
    }, 0);

    const longStayDiscount = getLongStayDiscount(totalNights);

    const results = roomPeriods.map(period => {
      const startDate = new Date(period.checkIn);
      const endDate = new Date(period.checkOut);
      const nights = differenceInDays(endDate, startDate);
      const baseRate = rates[formData.property][period.season][period.roomType];
      
      let rate = baseRate;
      if (period.capacity === '2') {
        rate *= 1.2;
      }

      return {
        ...period,
        checkIn: startDate,
        checkOut: endDate,
        nights,
        baseRate: rate, // This is the rate after capacity adjustment but before long-stay discount
        rate: rate * (1 - longStayDiscount),
        subtotal: rate * nights
      };
    });

    const subtotalBeforeDiscounts = results.reduce((sum, r) => sum + r.subtotal, 0);
    const longStayDiscountAmount = subtotalBeforeDiscounts * longStayDiscount;
    const subtotalAfterLongStay = subtotalBeforeDiscounts - longStayDiscountAmount;
    const extraDiscount = subtotalAfterLongStay * (formData.extraDiscount / 100);
    const totalBeforeVat = subtotalAfterLongStay - extraDiscount;
    const vat = totalBeforeVat * 0.07;
    const grandTotal = totalBeforeVat + vat;

    setCalculation({
      periods: results,
      subtotalBeforeDiscounts,
      longStayDiscountAmount,
      extraDiscount,
      vat,
      grandTotal,
      longStayDiscount: longStayDiscount * 100,
      totalNights
    });
  };

  const deleteRoomPeriod = (indexToDelete) => {
    setRoomPeriods(prev => prev.filter((_, index) => index !== indexToDelete));
  };

  const renderRoomPeriod = (period, index) => (
    <Box key={period.id} sx={{ mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2, justifyContent: 'space-between' }}>
        <Typography variant="h6">
          Room Period {index + 1}
        </Typography>
        {index > 0 && (
          <IconButton 
            onClick={() => deleteRoomPeriod(index)}
            color="error"
            size="small"
            sx={{ ml: 1 }}
          >
            <DeleteIcon />
          </IconButton>
        )}
      </Box>
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>Room Type</InputLabel>
            <Select
              value={period.roomType}
              label="Room Type"
              onChange={(e) => handleRoomPeriodChange(index, 'roomType', e.target.value)}
            >
              {getRoomTypes().map((type) => (
                <MenuItem key={type} value={type}>{type}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>Rate Type</InputLabel>
            <Select
              value={period.season}
              label="Rate Type"
              onChange={(e) => handleRoomPeriodChange(index, 'season', e.target.value)}
            >
              <MenuItem value="Rack">Rack</MenuItem>
              <MenuItem value="High">High</MenuItem>
              <MenuItem value="Medium">Medium</MenuItem>
              <MenuItem value="Low">Low</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>Capacity</InputLabel>
            <Select
              value={period.capacity}
              label="Capacity"
              onChange={(e) => handleRoomPeriodChange(index, 'capacity', e.target.value)}
            >
              <MenuItem value="1">1 Person</MenuItem>
              <MenuItem value="2">2 Persons (+20%)</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} md={6}>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <DatePicker
              label="Check-in Date"
              value={period.checkIn}
              onChange={(date) => handleRoomPeriodChange(index, 'checkIn', date)}
              renderInput={(params) => <TextField {...params} fullWidth />}
              minDate={index === 0 ? startOfToday() : roomPeriods[index - 1]?.checkOut || startOfToday()}
            />
            <DatePicker
              label="Check-out Date"
              value={period.checkOut}
              onChange={(date) => handleRoomPeriodChange(index, 'checkOut', date)}
              renderInput={(params) => <TextField {...params} fullWidth />}
              minDate={period.checkIn || startOfToday()}
              disabled={!period.checkIn}
            />
          </Box>
        </Grid>
      </Grid>
      {index < roomPeriods.length - 1 && <Divider sx={{ my: 3 }} />}
    </Box>
  );

  if (isAdmin) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Container maxWidth="lg">
          <Box sx={{ my: 4 }}>
            <Button 
              variant="outlined" 
              onClick={() => setIsAdmin(false)}
              sx={{ mb: 2 }}
            >
              Back to Calculator
            </Button>
            <AdminPanel onRatesUpdate={handleRatesUpdate} />
          </Box>
        </Container>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <LocalizationProvider dateAdapter={AdapterDateFns}>
        <Container maxWidth="lg">
          <Box sx={{ my: 4, minHeight: 'calc(100vh - 100px)', display: 'flex', flexDirection: 'column' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <Typography variant="h4" component="h1" gutterBottom>
                Alt Calculator
              </Typography>
              <Button 
                variant="outlined"
                onClick={() => setIsAdmin(true)}
              >
                Admin Panel
              </Button>
            </Box>
            
            <Paper sx={{ mb: 3, flex: 1 }}>
              <Box sx={{ mb: 3 }}>
                <FormControl fullWidth>
                  <InputLabel>Property</InputLabel>
                  <Select 
                    value={formData.property} 
                    label="Property" 
                    onChange={handleChange('property')}
                  >
                    <MenuItem value="Alt_CM">Alt Chiang Mai</MenuItem>
                    <MenuItem value="Alt_PR">Alt Ping River</MenuItem>
                  </Select>
                </FormControl>
              </Box>

              {roomPeriods.map((period, index) => renderRoomPeriod(period, index))}
              
              <Box sx={{ mb: 3 }}>
                <Button 
                  onClick={addRoomPeriod} 
                  variant="outlined" 
                  fullWidth
                  sx={{ height: 48 }}
                >
                  Add Room Period
                </Button>
              </Box>

              <Box sx={{ mb: 3 }}>
                <TextField
                  fullWidth
                  label="Extra Discount (%)"
                  type="number"
                  value={formData.extraDiscount}
                  onChange={handleChange('extraDiscount')}
                  InputProps={{ inputProps: { min: 0, max: 100 } }}
                />
              </Box>

              <Button
                variant="contained"
                fullWidth
                onClick={calculateTotal}
                sx={{ height: 48 }}
              >
                Calculate
              </Button>
            </Paper>

            {calculation && (
              <Box sx={{ mt: 3 }}>
                <Summary calculation={calculation} formData={formData} />
              </Box>
            )}
          </Box>

          <Box 
            component="footer" 
            sx={{ 
              py: 2, 
              textAlign: 'center',
              color: 'text.secondary',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px'
            }}
          >
            <div style={{ 
              fontSize: '1.1rem',
              fontWeight: 500
            }}>
              {weather && weather.main && weather.weather ? (
                `chiangmai: ${Math.round(weather.main.temp)}°C ${weather.weather[0].description}`
              ) : (
                'chiangmai: loading weather...'
              )}
            </div>
            <div style={{ 
              fontSize: '0.65rem',
              fontStyle: 'italic',
              marginTop: '4px'
            }}>
              designed by <Link
                component="button"
                onClick={() => setBusinessCardOpen(true)}
                sx={{ 
                  color: 'inherit',
                  textDecoration: 'none',
                  fontStyle: 'italic',
                  padding: 0,
                  fontSize: 'inherit',
                  '&:hover': {
                    textDecoration: 'underline',
                    cursor: 'pointer'
                  }
                }}
              >
                jeffrey
              </Link> • a gift to alt community
            </div>
          </Box>

          <BusinessCardDialog 
            open={businessCardOpen}
            onClose={() => setBusinessCardOpen(false)}
          />
        </Container>
      </LocalizationProvider>
    </ThemeProvider>
  );
}

export default App;
