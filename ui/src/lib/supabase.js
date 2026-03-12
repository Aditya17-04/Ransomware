import { createClient } from '@supabase/supabase-js'

const SUPABASE_URL = 'https://ynvrmxdxvftohepdugbw.supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InludnJteGR4dmZ0b2hlcGR1Z2J3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzMzMjQzNjUsImV4cCI6MjA4ODkwMDM2NX0.upcNi5r18K7lKBO3raviQ_BPCMEW6m0XuecQh19rMv0'

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
