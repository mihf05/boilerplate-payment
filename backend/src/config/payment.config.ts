import { registerAs } from '@nestjs/config';

export default registerAs('payment', () => ({
  defaultCurrency: process.env.DEFAULT_CURRENCY || 'USD',
  paymentProviders: {
    stripe: {
      secretKey: process.env.STRIPE_SECRET_KEY || '',
      webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
    },
    paypal: {
      clientId: process.env.PAYPAL_CLIENT_ID || '',
      clientSecret: process.env.PAYPAL_CLIENT_SECRET || '',
      sandbox: process.env.PAYPAL_SANDBOX === 'true',
    },
  },
}));