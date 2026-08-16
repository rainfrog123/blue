import React from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Link,
  Divider,
  ThemeProvider,
  createTheme,
  CssBaseline,
} from '@mui/material';
import { format } from 'date-fns';
import { bugReports } from './bugReports';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const theme = createTheme({
  palette: {
    primary: {
      main: '#007AFF',
    },
    background: {
      default: '#f5f5f7',
      paper: '#ffffff',
    },
    text: {
      primary: '#1d1d1f',
    }
  },
});

const BugReportBBS = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Box sx={{ mb: 4 }}>
          <Link
            href="/"
            sx={{
              display: 'flex',
              alignItems: 'center',
              color: 'text.primary',
              textDecoration: 'none',
              '&:hover': {
                color: 'primary.main',
              },
            }}
          >
            <ArrowBackIcon sx={{ mr: 1 }} />
            Back to Calculator
          </Link>
        </Box>

        <Typography variant="h4" gutterBottom align="center" sx={{ mb: 4 }}>
          Bug Reports & Feedback
        </Typography>

        {bugReports.length === 0 ? (
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography color="text.secondary">
              No bug reports yet. Be the first to report an issue!
            </Typography>
          </Paper>
        ) : (
          <Box>
            {bugReports.slice().reverse().map((report) => (
              <Paper key={report.id} sx={{ p: 3, mb: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Report #{report.id}
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary">
                    {format(new Date(report.date), 'MMM d, yyyy HH:mm')}
                  </Typography>
                </Box>
                <Divider sx={{ my: 1 }} />
                <Typography
                  sx={{
                    whiteSpace: 'pre-wrap',
                    fontFamily: 'monospace',
                    fontSize: '0.9rem',
                    lineHeight: 1.6,
                  }}
                >
                  {report.comment}
                </Typography>
              </Paper>
            ))}
          </Box>
        )}
      </Container>
    </ThemeProvider>
  );
};

export default BugReportBBS; 