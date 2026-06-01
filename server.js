/**
 * MentalBook — Render.com Server
 * Node.js + Express
 *
 * Handles:
 *   - Auth (register, login, password reset)
 *   - Subscription gate (Stripe checkout + webhooks)
 *   - Data proxy to Supabase (records, tasks, users)
 */

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const Stripe     = require('stripe');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase (service_role — full access, server only) ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// ── Stripe ──
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// ── Stripe plans ──
const PLANS = {
  pro:    { priceId: process.env.STRIPE_PRICE_PRO,    seats: 1 },
  clinic: { priceId: process.env.STRIPE_PRICE_CLINIC, seats: 5 },
};

// ── Middleware ──
app.use(cors({ origin: '*' }));
// Raw body needed for Stripe webhook signature
app.use('/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ── Simple auth middleware (JWT-less: token = base64 userId:email) ──
function requireAuth(req, res, next) {
  const token = req.headers['x-mb-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const [userId] = Buffer.from(token, 'base64').toString().split(':');
    req.userId = userId;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function makeToken(userId, email) {
  return Buffer.from(`${userId}:${email}`).toString('base64');
}

// ============================================================
// AUTH
// ============================================================

// POST /auth/register
app.post('/auth/register', async (req, res) => {
  const { email, nome, role, pass, crp, psicoCode } = req.body;
  if (!email || !nome || !role || !pass)
    return res.status(400).json({ error: 'Missing fields' });

  const emailLower = email.toLowerCase();

  // Check email already exists
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('email', emailLower)
    .single();

  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const passHash = await bcrypt.hash(pass, 10);

  // If patient, find psico by code
  let psicoId = null;
  if (role === 'paciente') {
    if (!psicoCode) return res.status(400).json({ error: 'Therapist code required' });
    const { data: psico } = await supabase
      .from('users')
      .select('id, status')
      .eq('code', psicoCode.toUpperCase())
      .single();
    if (!psico) return res.status(404).json({ error: 'Invalid therapist code' });
    if (psico.status !== 'approved')
      return res.status(403).json({ error: 'Therapist not approved yet' });
    psicoId = psico.id;
  }

  // Generate linking code for psychologists
  const code = role === 'psicologo'
    ? 'PSI-' + Math.random().toString(36).slice(2,6).toUpperCase()
    : null;

  const status = role === 'psicologo' ? 'pending' : 'approved';

  const { data: user, error } = await supabase
    .from('users')
    .insert({
      email: emailLower,
      nome,
      role,
      pass_hash: passHash,
      crp: crp || null,
      code,
      status,
      psico_id: psicoId,
      created_at: new Date().toISOString(),
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  // Create trial subscription for psychologists
  if (role === 'psicologo') {
    const trialEnd = new Date(Date.now() + 30 * 86400000);
    await supabase.from('subscriptions').insert({
      user_id: user.id,
      plan: 'pro',
      status: 'trialing',
      trial_end: trialEnd.toISOString(),
    });
  }

  return res.status(201).json({
    message: role === 'psicologo'
      ? 'Registration submitted, awaiting admin approval'
      : 'Account created',
    userId: user.id,
  });
});

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { email, pass } = req.body;
  if (!email || !pass)
    return res.status(400).json({ error: 'Missing email or password' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();

  if (error || !user)
    return res.status(401).json({ error: 'Incorrect email or password' });

  const match = await bcrypt.compare(pass, user.pass_hash);
  if (!match)
    return res.status(401).json({ error: 'Incorrect email or password' });

  if (user.role === 'psicologo' && user.status === 'pending')
    return res.status(403).json({ error: 'pending', message: 'Awaiting admin approval' });

  if (user.role === 'psicologo' && user.status === 'rejected')
    return res.status(403).json({ error: 'rejected', message: 'Registration rejected' });

  // Update last visit
  await supabase
    .from('users')
    .update({ last_visit: new Date().toISOString() })
    .eq('id', user.id);

  // Get subscription status for psychologists
  let subscription = null;
  if (user.role === 'psicologo' && !user.is_admin) {
    const { data: sub } = await supabase
      .from('subscriptions')
      .select('*')
      .eq('user_id', user.id)
      .single();
    subscription = sub;
  }

  const token = makeToken(user.id, user.email);
  const { pass_hash, ...safeUser } = user;

  return res.json({
    token,
    user: { ...safeUser, subscription },
  });
});

// POST /auth/forgot-password
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const { data: user } = await supabase
    .from('users')
    .select('id, nome, email')
    .eq('email', email.toLowerCase())
    .single();

  if (!user) return res.status(404).json({ error: 'Email not found' });

  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let temp = '';
  for (let i = 0; i < 8; i++) temp += chars[Math.floor(Math.random() * chars.length)];

  const hash = await bcrypt.hash(temp, 10);
  await supabase
    .from('users')
    .update({ pass_hash: hash, must_change_password: true })
    .eq('id', user.id);

  return res.json({ userId: user.id, tempPassword: temp, nome: user.nome });
});

// POST /auth/change-password
app.post('/auth/change-password', requireAuth, async (req, res) => {
  const { newPass } = req.body;
  if (!newPass || newPass.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const hash = await bcrypt.hash(newPass, 10);
  await supabase
    .from('users')
    .update({ pass_hash: hash, must_change_password: false })
    .eq('id', req.userId);

  return res.json({ success: true });
});

// ============================================================
// USERS
// ============================================================

// GET /users/me
app.get('/users/me', requireAuth, async (req, res) => {
  const { data: user, error } = await supabase
    .from('users')
    .select('id, email, nome, role, crp, code, status, is_admin, psico_id, must_change_password, created_at, last_visit')
    .eq('id', req.userId)
    .single();

  if (error || !user) return res.status(404).json({ error: 'User not found' });
  return res.json(user);
});

// GET /users/patients — psico gets their own patients
app.get('/users/patients', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, nome, role, status, created_at')
    .eq('psico_id', req.userId)
    .eq('role', 'paciente');

  if (error) return res.status(500).json({ error: error.message });
  return res.json(data || []);
});

// GET /users/pending — admin gets pending psychologists
app.get('/users/pending', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, nome, crp, status, created_at')
    .eq('role', 'psicologo')
    .in('status', ['pending', 'approved', 'rejected'])
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  return res.json(data || []);
});

// PATCH /users/:id/status — admin approves/rejects psychologist
app.patch('/users/:id/status', requireAuth, async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status))
    return res.status(400).json({ error: 'Invalid status' });

  await supabase
    .from('users')
    .update({ status })
    .eq('id', req.params.id);

  return res.json({ success: true });
});

// ============================================================
// RECORDS
// ============================================================

// GET /records?patientId=xxx
app.get('/records', requireAuth, async (req, res) => {
  const { patientId } = req.query;
  let query = supabase.from('records').select('*').order('created_at', { ascending: false });

  if (patientId) {
    query = query.eq('patient_id', patientId);
  } else {
    // Patient gets their own; psico gets all their patients'
    query = query.or(`patient_id.eq.${req.userId},psico_id.eq.${req.userId}`);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  return res.json(data || []);
});

// POST /records
app.post('/records', requireAuth, async (req, res) => {
  const r = req.body;
  const { data, error } = await supabase
    .from('records')
    .insert({
      patient_id:          r.patientId,
      psico_id:            r.psicoId || null,
      situacao:            r.situacao,
      pensamentos:         r.pensamentos,
      emotions:            r.emotions || [],
      distortions:         r.distortions || [],
      crenca:              r.crenca,
      crenca_nova:         r.crencaNova,
      intensidade:         r.intensidade,
      intensidade_nova:    r.intensidadeNova,
      ev_apoia:            r.evApoia,
      ev_contra:           r.evContra,
      resposta_adaptativa: r.respostaAdaptativa,
      obs:                 r.obs,
      data_hora:           r.dataHora,
      is_new:              true,
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  return res.status(201).json(data);
});

// PATCH /records/:id
app.patch('/records/:id', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('records')
    .update(req.body)
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  return res.json(data);
});

// ============================================================
// TASKS
// ============================================================

// GET /tasks?patientId=xxx
app.get('/tasks', requireAuth, async (req, res) => {
  const { patientId } = req.query;
  const { data, error } = await supabase
    .from('tasks')
    .select('*')
    .eq('patient_id', patientId || req.userId);

  if (error) return res.status(500).json({ error: error.message });
  return res.json(data || []);
});

// POST /tasks
app.post('/tasks', requireAuth, async (req, res) => {
  const { patientId, taskType, config } = req.body;
  const { data, error } = await supabase
    .from('tasks')
    .upsert({
      patient_id: patientId,
      psico_id:   req.userId,
      task_type:  taskType,
      active:     true,
      config:     config || {},
    }, { onConflict: 'patient_id,task_type' })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  return res.status(201).json(data);
});

// DELETE /tasks
app.delete('/tasks', requireAuth, async (req, res) => {
  const { patientId, taskType } = req.body;
  await supabase
    .from('tasks')
    .update({ active: false })
    .eq('patient_id', patientId)
    .eq('task_type', taskType);

  return res.json({ success: true });
});

// ============================================================
// SUBMISSIONS
// ============================================================

// GET /submissions?patientId=xxx&taskType=xxx
app.get('/submissions', requireAuth, async (req, res) => {
  const { patientId, taskType } = req.query;
  let query = supabase
    .from('submissions')
    .select('*')
    .eq('patient_id', patientId || req.userId)
    .order('created_at', { ascending: false });

  if (taskType) query = query.eq('task_type', taskType);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  return res.json(data || []);
});

// POST /submissions
app.post('/submissions', requireAuth, async (req, res) => {
  const { taskType, data: submissionData } = req.body;
  const { data, error } = await supabase
    .from('submissions')
    .insert({
      patient_id: req.userId,
      task_type:  taskType,
      data:       submissionData,
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  return res.status(201).json(data);
});

// ============================================================
// STRIPE — Checkout
// ============================================================

// POST /stripe/create-checkout
app.post('/stripe/create-checkout', requireAuth, async (req, res) => {
  const { plan, successUrl, cancelUrl } = req.body;
  if (!PLANS[plan]) return res.status(400).json({ error: 'Invalid plan' });

  const { data: user } = await supabase
    .from('users')
    .select('email, nome')
    .eq('id', req.userId)
    .single();

  try {
    // Get or create Stripe customer
    let customerId;
    const { data: sub } = await supabase
      .from('subscriptions')
      .select('stripe_customer_id')
      .eq('user_id', req.userId)
      .single();

    if (sub?.stripe_customer_id) {
      customerId = sub.stripe_customer_id;
    } else {
      const customer = await stripe.customers.create({
        email:    user.email,
        name:     user.nome,
        metadata: { userId: req.userId, plan },
      });
      customerId = customer.id;
    }

    const session = await stripe.checkout.sessions.create({
      customer:             customerId,
      payment_method_types: ['card'],
      line_items: [{ price: PLANS[plan].priceId, quantity: 1 }],
      mode:        'subscription',
      success_url: successUrl,
      cancel_url:  cancelUrl,
      metadata:    { userId: req.userId, plan },
      locale:      'auto',
    });

    return res.json({ sessionId: session.id, url: session.url });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /stripe/webhook — receives Stripe events
app.post('/stripe/webhook', async (req, res) => {
  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  const data = event.data.object;

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const userId = data.metadata?.userId;
        const plan   = data.metadata?.plan || 'pro';
        if (!userId) break;

        const sub = await stripe.subscriptions.retrieve(data.subscription);
        await supabase.from('subscriptions').upsert({
          user_id:                userId,
          stripe_customer_id:     data.customer,
          stripe_subscription_id: data.subscription,
          plan,
          status:                 sub.status,
          trial_end:              sub.trial_end    ? new Date(sub.trial_end    * 1000).toISOString() : null,
          current_period_end:     sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null,
          seats:                  PLANS[plan].seats,
          updated_at:             new Date().toISOString(),
        }, { onConflict: 'user_id' });
        break;
      }
      case 'customer.subscription.updated': {
        const userId = data.metadata?.userId;
        if (!userId) break;
        await supabase.from('subscriptions')
          .update({
            status:             data.status,
            current_period_end: new Date(data.current_period_end * 1000).toISOString(),
            cancel_at_period_end: data.cancel_at_period_end,
            updated_at:         new Date().toISOString(),
          })
          .eq('user_id', userId);
        break;
      }
      case 'customer.subscription.deleted': {
        const userId = data.metadata?.userId;
        if (!userId) break;
        await supabase.from('subscriptions')
          .update({ status: 'canceled', updated_at: new Date().toISOString() })
          .eq('user_id', userId);
        break;
      }
      case 'invoice.payment_failed': {
        const { data: users } = await supabase
          .from('subscriptions')
          .select('user_id')
          .eq('stripe_customer_id', data.customer)
          .limit(1);
        if (users?.[0]) {
          await supabase.from('subscriptions')
            .update({ status: 'past_due', updated_at: new Date().toISOString() })
            .eq('user_id', users[0].user_id);
        }
        break;
      }
    }
    return res.json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    return res.status(500).json({ error: err.message });
  }
});

// GET /subscription/status
app.get('/subscription/status', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('subscriptions')
    .select('*')
    .eq('user_id', req.userId)
    .single();

  if (error || !data) return res.json({ status: 'none' });
  return res.json(data);
});

// POST /subscription/cancel
app.post('/subscription/cancel', requireAuth, async (req, res) => {
  const { data: sub } = await supabase
    .from('subscriptions')
    .select('stripe_subscription_id')
    .eq('user_id', req.userId)
    .single();

  if (!sub?.stripe_subscription_id)
    return res.status(404).json({ error: 'No active subscription' });

  await stripe.subscriptions.update(sub.stripe_subscription_id, {
    cancel_at_period_end: true,
  });
  await supabase.from('subscriptions')
    .update({ cancel_at_period_end: true, updated_at: new Date().toISOString() })
    .eq('user_id', req.userId);

  return res.json({ success: true });
});

// ── Health check ──
app.get('/health', (_, res) => res.json({ status: 'ok', service: 'MentalBook API' }));

app.listen(PORT, () => console.log(`MentalBook API running on port ${PORT}`));
