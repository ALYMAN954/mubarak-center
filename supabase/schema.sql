-- نظام متابعة دورات التجويد: مخطط قاعدة البيانات وقواعد الحماية
-- الصق هذا الملف كاملاً في Supabase ← SQL Editor ← Run (مرة واحدة)

create extension if not exists pgcrypto;

-- الحسابات: كل أستاذ أو مشرف له حساب دخول (Supabase Auth) وملف تعريف هنا
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  login_key   text unique not null,
  role        text not null check (role in ('supervisor','teacher')),
  name        text not null,
  circle_id   text,
  circle_ids  text[] not null default '{}',
  must_change boolean not null default false,
  created_at  timestamptz not null default now()
);

-- كل بيانات التطبيق: الإعدادات، الطلاب، الجلسات، سجل التعديلات
create table if not exists public.docs (
  coll       text not null,
  id         text not null,
  circle_id  text,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (coll, id)
);
create index if not exists docs_circle_idx on public.docs (coll, circle_id);
create index if not exists docs_updated_idx on public.docs (coll, updated_at desc);

alter table public.profiles enable row level security;
alter table public.docs enable row level security;

-- دوال مساعدة تقرأ دور المستخدم ودورته (بصلاحية النظام لتجنب التكرار الذاتي)
create or replace function public.my_role() returns text
  language sql stable security definer set search_path = public as
$$ select role from public.profiles where id = auth.uid() $$;

create or replace function public.my_circles() returns text[]
  language sql stable security definer set search_path = public as
$$ select coalesce(nullif(circle_ids,'{}'), case when circle_id is null then '{}'::text[] else array[circle_id] end)
   from public.profiles where id = auth.uid() $$;

create or replace function public.my_circle() returns text
  language sql stable security definer set search_path = public as
$$ select circle_id from public.profiles where id = auth.uid() $$;

-- ===== قواعد الحماية =====
drop policy if exists profiles_select on public.profiles;
drop policy if exists profiles_sup_write on public.profiles;
create policy profiles_select on public.profiles for select
  using (id = auth.uid() or public.my_role() = 'supervisor');
create policy profiles_sup_write on public.profiles for all
  using (public.my_role() = 'supervisor') with check (public.my_role() = 'supervisor');

drop policy if exists docs_sup_all on public.docs;
drop policy if exists docs_teacher_select on public.docs;
drop policy if exists docs_teacher_insert on public.docs;
drop policy if exists docs_teacher_update on public.docs;
-- المشرف: كل شيء
create policy docs_sup_all on public.docs for all
  using (public.my_role() = 'supervisor') with check (public.my_role() = 'supervisor');
-- الأستاذ: يقرأ الإعدادات، ويقرأ ويكتب بيانات دوراته فقط
create policy docs_teacher_select on public.docs for select
  using (public.my_role() = 'teacher' and
         (coll = 'cfg' or (coll in ('students','records','audit') and circle_id = any(public.my_circles()))));
create policy docs_teacher_insert on public.docs for insert
  with check (public.my_role() = 'teacher' and coll in ('students','records','audit')
              and circle_id = any(public.my_circles()));
create policy docs_teacher_update on public.docs for update
  using (public.my_role() = 'teacher' and coll in ('students','records') and circle_id = any(public.my_circles()))
  with check (public.my_role() = 'teacher' and coll in ('students','records') and circle_id = any(public.my_circles()));

-- ===== دوال تُستدعى من التطبيق =====
-- قبل الدخول: أسماء الحسابات فقط (لقائمة الاختيار) وهل النظام يحتاج إعداداً أولياً
create or replace function public.login_names()
  returns table (login_key text, name text, role text)
  language sql stable security definer set search_path = public as
$$ select login_key, name, role from public.profiles order by name $$;

create or replace function public.needs_setup() returns boolean
  language sql stable security definer set search_path = public as
$$ select not exists (select 1 from public.profiles) $$;

create or replace function public.public_header() returns jsonb
  language sql stable security definer set search_path = public as
$$ select data->'header' from public.docs where coll = 'cfg' and id = 'main' $$;

-- أول حساب يُنشأ يصبح المشرف العام (تعمل مرة واحدة فقط)
create or replace function public.claim_first_supervisor(p_name text, p_key text) returns void
  language plpgsql security definer set search_path = public as
$$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if exists (select 1 from public.profiles) then raise exception 'already set up'; end if;
  insert into public.profiles (id, login_key, role, name) values (auth.uid(), p_key, 'supervisor', p_name);
end $$;

-- الأستاذ يختار دورته أول مرة فقط
create or replace function public.set_my_circle(cid text) returns void
  language plpgsql security definer set search_path = public as
$$
begin
  if public.my_role() is distinct from 'teacher' then raise exception 'not a teacher'; end if;
  update public.profiles set circle_id = cid where id = auth.uid() and circle_id is null;
end $$;

create or replace function public.clear_must_change() returns void
  language sql security definer set search_path = public as
$$ update public.profiles set must_change = false where id = auth.uid() $$;

-- المشرف يعيد تعيين كلمة سر حساب (يصبح مؤقتاً ويُطلب من الأستاذ تغييره)
create or replace function public.admin_set_password(uid uuid, pw text) returns void
  language plpgsql security definer set search_path = public, auth, extensions as
$$
begin
  if public.my_role() is distinct from 'supervisor' then raise exception 'not allowed'; end if;
  if length(pw) < 6 then raise exception 'password too short'; end if;
  update auth.users set encrypted_password = crypt(pw, gen_salt('bf')), updated_at = now() where id = uid;
  update public.profiles set must_change = true where id = uid and role = 'teacher';
end $$;

-- المشرف يحذف حساباً (لا يحذف نفسه)
create or replace function public.admin_delete_user(uid uuid) returns void
  language plpgsql security definer set search_path = public, auth as
$$
begin
  if public.my_role() is distinct from 'supervisor' then raise exception 'not allowed'; end if;
  if uid = auth.uid() then raise exception 'cannot delete yourself'; end if;
  delete from auth.users where id = uid;
end $$;

-- رابط الطالب: يعيد بيانات الطالب الواحد فقط دون ملاحظات الأستاذ ودون بيانات غيره
create or replace function public.student_view(tok text) returns jsonb
  language plpgsql stable security definer set search_path = public as
$$
declare s public.docs; c public.docs;
begin
  if tok is null or length(tok) < 10 then return null; end if;
  select * into s from public.docs where coll = 'students' and data->>'token' = tok limit 1;
  if not found then return null; end if;
  select * into c from public.docs where coll = 'cfg' and id = 'main';
  return jsonb_build_object(
    'student', jsonb_build_object('id', s.id, 'name', s.data->'name', 'circleId', s.data->'circleId',
                                  'degree', s.data->'degree', 'active', s.data->'active', 'token', tok),
    'cfg', jsonb_build_object('header', c.data->'header', 'settings', c.data->'settings', 'circles', c.data->'circles'),
    'records', (
      select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'data', jsonb_build_object(
        'cid', r.data->'cid', 'date', r.data->'date', 'meta', (r.data->'meta') - 'notes',
        'rows', jsonb_build_object(s.id, (r.data->'rows'->s.id) - 'note')))), '[]'::jsonb)
      from public.docs r
      where r.coll = 'records' and r.circle_id = s.circle_id and (r.data->'rows') ? s.id));
end $$;

-- صلاحيات التنفيذ
revoke all on function public.admin_set_password(uuid, text) from public, anon;
revoke all on function public.admin_delete_user(uuid) from public, anon;
revoke all on function public.claim_first_supervisor(text, text) from public, anon;
revoke all on function public.set_my_circle(text) from public, anon;
revoke all on function public.clear_must_change() from public, anon;
grant execute on function public.admin_set_password(uuid, text) to authenticated;
grant execute on function public.admin_delete_user(uuid) to authenticated;
grant execute on function public.claim_first_supervisor(text, text) to authenticated;
grant execute on function public.set_my_circle(text) to authenticated;
revoke all on function public.my_circles() from public, anon;
grant execute on function public.my_circles() to authenticated;
grant execute on function public.clear_must_change() to authenticated;
grant execute on function public.login_names() to anon, authenticated;
grant execute on function public.needs_setup() to anon, authenticated;
grant execute on function public.public_header() to anon, authenticated;
grant execute on function public.student_view(text) to anon, authenticated;

-- التحديث الفوري بين الأجهزة
do $$ begin
  begin alter publication supabase_realtime add table public.docs; exception when others then null; end;
  begin alter publication supabase_realtime add table public.profiles; exception when others then null; end;
end $$;
