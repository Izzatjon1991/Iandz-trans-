
-- I&Z Trans TMS database

create table if not exists public.iz_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default '',
  role text not null default 'driver'
    check (role in ('admin', 'dispatcher', 'driver'))
);

create table if not exists public.iz_dispatchers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  commission numeric not null default 1.5
    check (commission between 0 and 100)
);

create table if not exists public.iz_drivers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  truck text,
  status text default 'Available',
  user_id uuid unique references auth.users(id)
);

create table if not exists public.iz_loads (
  id uuid primary key default gen_random_uuid(),
  load_number text,
  truck text,
  driver_id uuid references public.iz_drivers(id)
    on delete set null,
  dispatcher_id uuid references public.iz_dispatchers(id)
    on delete set null,
  broker text,
  pickup text,
  delivery text,
  pickup_date date,
  delivery_date date,
  rate numeric default 0 check (rate >= 0),
  driver_pay numeric default 0 check (driver_pay >= 0),
  status text default 'Booked',
  created_at timestamptz default now()
);

create table if not exists public.iz_fuel (
  id uuid primary key default gen_random_uuid(),
  truck text,
  date date,
  station text,
  gallons numeric default 0 check (gallons >= 0),
  cost numeric default 0 check (cost >= 0),
  odometer numeric default 0 check (odometer >= 0)
);

create table if not exists public.iz_repairs (
  id uuid primary key default gen_random_uuid(),
  truck text,
  date date,
  shop text,
  description text,
  parts numeric default 0 check (parts >= 0),
  labor numeric default 0 check (labor >= 0)
);

-- Employee role lookup
create or replace function public.iz_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select role
  from public.iz_profiles
  where id = (select auth.uid())
$$;

revoke all on function public.iz_role() from public;
grant execute on function public.iz_role() to authenticated;

-- Enable Row Level Security
alter table public.iz_profiles enable row level security;
alter table public.iz_dispatchers enable row level security;
alter table public.iz_drivers enable row level security;
alter table public.iz_loads enable row level security;
alter table public.iz_fuel enable row level security;
alter table public.iz_repairs enable row level security;

-- Profiles: self read, admin management
create policy "iz_profiles_read" on public.iz_profiles
for select to authenticated
using (
  id = (select auth.uid())
  or (select public.iz_role()) = 'admin'
);

create policy "iz_profiles_admin_insert" on public.iz_profiles
for insert to authenticated
with check ((select public.iz_role()) = 'admin');

create policy "iz_profiles_admin_update" on public.iz_profiles
for update to authenticated
using ((select public.iz_role()) = 'admin')
with check ((select public.iz_role()) = 'admin');

-- Dispatchers: admin writes, managers read
create policy "iz_dispatchers_read" on public.iz_dispatchers
for select to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_dispatchers_insert" on public.iz_dispatchers
for insert to authenticated
with check ((select public.iz_role()) = 'admin');

create policy "iz_dispatchers_update" on public.iz_dispatchers
for update to authenticated
using ((select public.iz_role()) = 'admin')
with check ((select public.iz_role()) = 'admin');

create policy "iz_dispatchers_delete" on public.iz_dispatchers
for delete to authenticated
using ((select public.iz_role()) = 'admin');

-- Drivers: managers read/write, driver reads own
create policy "iz_drivers_read" on public.iz_drivers
for select to authenticated
using (
  (select public.iz_role()) in ('admin', 'dispatcher')
  or user_id = (select auth.uid())
);

create policy "iz_drivers_insert" on public.iz_drivers
for insert to authenticated
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_drivers_update" on public.iz_drivers
for update to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'))
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_drivers_delete" on public.iz_drivers
for delete to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'));

-- Loads: managers read/write, driver reads assigned
create policy "iz_loads_read" on public.iz_loads
for select to authenticated
using (
  (select public.iz_role()) in ('admin', 'dispatcher')
  or exists (
    select 1 from public.iz_drivers d
    where d.id = driver_id
      and d.user_id = (select auth.uid())
  )
);

create policy "iz_loads_insert" on public.iz_loads
for insert to authenticated
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_loads_update" on public.iz_loads
for update to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'))
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_loads_delete" on public.iz_loads
for delete to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'));

-- Fuel: managers only
create policy "iz_fuel_read" on public.iz_fuel
for select to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_fuel_insert" on public.iz_fuel
for insert to authenticated
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_fuel_update" on public.iz_fuel
for update to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'))
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_fuel_delete" on public.iz_fuel
for delete to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'));

-- Repairs: managers only
create policy "iz_repairs_read" on public.iz_repairs
for select to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_repairs_insert" on public.iz_repairs
for insert to authenticated
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_repairs_update" on public.iz_repairs
for update to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'))
with check ((select public.iz_role()) in ('admin', 'dispatcher'));

create policy "iz_repairs_delete" on public.iz_repairs
for delete to authenticated
using ((select public.iz_role()) in ('admin', 'dispatcher'));
