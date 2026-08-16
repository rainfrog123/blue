import { differenceInDays } from 'date-fns';
import { RATES_DATA } from '../constants/rates';

export const getLongStayDiscount = (totalNights) => {
  if (totalNights >= 29) return 50;
  if (totalNights >= 19) return 35;
  if (totalNights >= 9) return 20;
  return 0;
};

export const calculatePeriods = (formData) => {
  console.log('Calculating periods with formData:', formData);
  const periods = [];
  
  if (formData.calculationType === 'extension') {
    console.log('Extension mode detected');
    const startDate = formData.originalCheckOut ? new Date(formData.originalCheckOut) : null;
    const endDate = formData.checkOut ? new Date(formData.checkOut) : null;
    
    console.log('Extension dates:', {
      startDate,
      endDate,
      originalCheckOut: formData.originalCheckOut,
      checkOut: formData.checkOut
    });
    
    if (startDate && endDate && 
        startDate.getFullYear() > 1970 && 
        endDate.getFullYear() > 1970 && 
        !isNaN(startDate) && 
        !isNaN(endDate)) {
      console.log('Valid dates found, creating period');
      periods.push({
        startDate,
        endDate,
        roomType: formData.roomType,
        capacity: formData.capacity,
        nights: differenceInDays(endDate, startDate)
      });
    } else {
      console.log('Date validation failed:', {
        hasStartDate: !!startDate,
        hasEndDate: !!endDate,
        startDateYear: startDate?.getFullYear(),
        endDateYear: endDate?.getFullYear(),
        isStartDateValid: !isNaN(startDate),
        isEndDateValid: !isNaN(endDate)
      });
    }
  } else {
    // Original logic for new bookings
    let currentDate = new Date(formData.checkIn);
    const endDate = new Date(formData.checkOut);
    
    let currentPeriod = {
      startDate: currentDate,
      roomType: formData.roomType,
      capacity: formData.capacity
    };

    if (formData.roomChanges) {
      formData.roomChanges.forEach(change => {
        const changeDate = new Date(change.date);
        currentPeriod.endDate = changeDate;
        currentPeriod.nights = differenceInDays(currentPeriod.endDate, currentPeriod.startDate);
        periods.push(currentPeriod);

        currentPeriod = {
          startDate: changeDate,
          roomType: change.roomType,
          capacity: change.capacity || formData.capacity
        };
      });
    }

    // Final period
    currentPeriod.endDate = endDate;
    currentPeriod.nights = differenceInDays(currentPeriod.endDate, currentPeriod.startDate);
    periods.push(currentPeriod);
  }

  return periods;
};

export const calculatePrice = (formData) => {
  const periods = calculatePeriods(formData);
  const totalNights = periods.reduce((sum, period) => sum + period.nights, 0);
  
  // Determine long-stay discount eligibility
  let applyLongStayDiscount = formData.calculationType === 'new' || 
    (formData.calculationType === 'extension' && 
      (formData.overrideSevenDayRule || 
        differenceInDays(new Date(), new Date(formData.originalCheckIn)) <= 7));

  const longStayDiscount = applyLongStayDiscount ? getLongStayDiscount(totalNights) : 0;
  let subtotal = 0;

  // Calculate each period
  periods.forEach(period => {
    const baseRate = RATES_DATA[formData.property][formData.season][period.roomType];
    let rate = baseRate;

    // Apply capacity surcharge
    if (period.capacity === '2') {
      rate *= 1.2;
    }

    // Apply long-stay discount
    if (applyLongStayDiscount) {
      rate *= (1 - longStayDiscount / 100);
    }

    // Apply extra discount
    if (formData.extraDiscount > 0) {
      rate *= (1 - formData.extraDiscount / 100);
    }

    period.rate = rate;
    period.subtotal = rate * period.nights;
    subtotal += period.subtotal;
  });

  // Calculate VAT and total
  const vat = subtotal * 0.07;
  const total = subtotal + vat;

  return {
    periods,
    subtotal,
    vat,
    total,
    longStayDiscount: applyLongStayDiscount ? longStayDiscount : 0
  };
}; 