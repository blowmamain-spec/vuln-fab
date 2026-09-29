CREATE TABLE public.a (id integer);
CREATE TABLE public.b (id integer);
ALTER TABLE public.b ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_db ON public.b USING (true);
CREATE TABLE public.dashboard_made (id integer);
