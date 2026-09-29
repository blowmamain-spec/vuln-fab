SET statement_timeout = 0;
CREATE TABLE public.a (id integer);
ALTER TABLE public.a ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.a USING (true);
CREATE TABLE auth.internal (id integer);
CREATE TABLE private.other (id integer);
COMMENT ON TABLE public.a IS 'x';
