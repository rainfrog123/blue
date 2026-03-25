import React from 'react';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Divider
} from '@mui/material';
import { format } from 'date-fns';

const Summary = ({ calculation, formData }) => {
  const formatDate = (date) => {
    console.log('Formatting date:', date);
    if (!date) {
      console.log('Date is null/undefined');
      return 'Invalid Date';
    }
    const parsedDate = new Date(date);
    console.log('Parsed date:', parsedDate);
    console.log('Parsed date year:', parsedDate.getFullYear());
    console.log('Is date valid:', !isNaN(parsedDate.getTime()));
    
    if (isNaN(parsedDate.getTime()) || parsedDate.getFullYear() <= 1970) {
      console.log('Date validation failed');
      return 'Invalid Date';
    }
    return format(parsedDate, 'dd MMM yyyy');
  };
  const formatCurrency = (amount) => 
    new Intl.NumberFormat('th-TH', { 
      style: 'currency', 
      currency: 'THB',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);

  const season = calculation.periods[0]?.season || 'N/A';

  return (
    <Box>
      <Typography variant="h6" gutterBottom>Calculation Summary</Typography>
      
      <Paper elevation={1} sx={{ p: 2, mb: 3 }}>
        <Typography variant="subtitle1" gutterBottom>
          Property: {formData.property === 'Alt_CM' ? 'Alt Chiang Mai' : 'Alt Ping River'}
        </Typography>
        <Typography variant="subtitle1" gutterBottom>
          Rate Type: {season}
        </Typography>
      </Paper>

      <TableContainer component={Paper} sx={{ mb: 3 }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Period</TableCell>
              <TableCell>Room Type</TableCell>
              <TableCell>Capacity</TableCell>
              <TableCell align="right">Rate</TableCell>
              <TableCell align="right">Nights</TableCell>
              <TableCell align="right">Subtotal</TableCell>
              <TableCell align="right">Discounts</TableCell>
              <TableCell align="right">Final Amount</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {calculation.periods.map((period, index) => {
              const subtotal = period.baseRate * period.nights;
              const longStayDiscount = subtotal * (calculation.longStayDiscount / 100);
              const subtotalAfterLongStay = subtotal - longStayDiscount;
              const extraDiscount = subtotalAfterLongStay * (formData.extraDiscount / 100);
              const totalDiscounts = longStayDiscount + extraDiscount;
              const finalAmount = subtotal - totalDiscounts;

              return (
                <TableRow key={index}>
                  <TableCell>
                    {formatDate(period.startDate || period.checkIn)} - {formatDate(period.endDate || period.checkOut)}
                  </TableCell>
                  <TableCell>{period.roomType}</TableCell>
                  <TableCell>
                    {period.capacity} {period.capacity === '2' && '(+20%)'}
                  </TableCell>
                  <TableCell align="right">{formatCurrency(period.baseRate)}</TableCell>
                  <TableCell align="right">{period.nights}</TableCell>
                  <TableCell align="right">{formatCurrency(subtotal)}</TableCell>
                  <TableCell align="right" sx={{ color: 'error.main' }}>
                    -{formatCurrency(totalDiscounts)}
                  </TableCell>
                  <TableCell align="right">{formatCurrency(finalAmount)}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>

      <Paper elevation={1} sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <Typography variant="subtitle1">
            Total Nights: {calculation.totalNights}
          </Typography>
          <Divider sx={{ my: 1 }} />
          <Typography variant="subtitle1">
            Subtotal: {formatCurrency(calculation.subtotalBeforeDiscounts)}
          </Typography>
          {calculation.longStayDiscount > 0 && (
            <Typography variant="subtitle1" color="error">
              Long-stay Discount ({calculation.longStayDiscount}%): -{formatCurrency(calculation.longStayDiscountAmount)}
            </Typography>
          )}
          {formData.extraDiscount > 0 && (
            <Typography variant="subtitle1" color="error">
              Extra Discount ({formData.extraDiscount}%): -{formatCurrency(calculation.extraDiscount)}
            </Typography>
          )}
          <Typography variant="subtitle1">
            VAT (7%): {formatCurrency(calculation.vat)}
          </Typography>
          <Typography variant="h6" sx={{ mt: 1 }}>
            Total: {formatCurrency(calculation.grandTotal)}
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
};

export default Summary; 