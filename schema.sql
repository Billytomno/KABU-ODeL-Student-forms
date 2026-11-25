create table if not exists students(reg text primary key, name text not null, email text unique not null, pw_hash text);
create table if not exists staff(id serial primary key, username text unique not null, name text not null, email text,
  pw_hash text not null, role text not null check (role in ('station','hod','odel','registrar','admin')), station int);
create table if not exists clearance(id serial primary key, reg text not null, name text not null, programme text, grp text,
  school text, level text, mode text, created_at timestamptz default now(), registrar_by text, registrar_at timestamptz);
create table if not exists clearance_steps(clearance_id int references clearance(id) on delete cascade, station int,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  officer text, comment text, decided_at timestamptz, primary key(clearance_id, station));
create table if not exists missing_marks(id serial primary key, reg text not null, name text not null, school text,
  dept_station int not null, tel text, created_at timestamptz default now(),
  status text not null default 'pending' check (status in ('pending','final')),
  fin_by text, fin_at timestamptz, outcome text, remarks text);
create table if not exists mm_units(id serial primary key, mm_id int references missing_marks(id) on delete cascade,
  code text, descr text, semester text, exam_type text, lecturer text, cat_mark text, exam_mark text, examiner_sig text);
create table if not exists dept_email(station int primary key, email text not null);
create table if not exists settings(key text primary key, value text);
create table if not exists reset_codes(reg text primary key, code_hash text not null, expires_at timestamptz not null);
create table if not exists audit(id serial primary key, at timestamptz default now(), actor text, action text, detail jsonb);
create index if not exists steps_pending on clearance_steps(station) where status='pending';
create index if not exists clearance_reg on clearance(reg);
create index if not exists mm_reg on missing_marks(reg);
create or replace view mm_full as
  select m.*, (select json_agg(json_build_object('id',x.id,'code',x.code,'descr',x.descr,'semester',x.semester,'exam_type',x.exam_type,
    'lecturer',x.lecturer,'cat',x.cat_mark,'exam',x.exam_mark,'sig',x.examiner_sig) order by x.id) from mm_units x where x.mm_id=m.id) units
  from missing_marks m;
create table if not exists login_attempts(key text primary key, fails int not null default 0, locked_until timestamptz);
