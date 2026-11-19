-- ترحيل v5: دعم أكثر من دورة للأستاذ الواحد
-- شغّله مرة واحدة في Supabase > SQL Editor قبل رفع الملفات الجديدة. آمن عند التكرار.
alter table public.profiles add column if not exists circle_ids text[] not null default '{}';
update public.profiles set circle_ids = array[circle_id]
  where circle_id is not null and coalesce(array_length(circle_ids,1),0)=0;

create or replace function public.my_circles() returns text[]
  language sql stable security definer set search_path = public as
$$ select coalesce(nullif(circle_ids,'{}'), case when circle_id is null then '{}'::text[] else array[circle_id] end)
   from public.profiles where id = auth.uid() $$;
revoke all on function public.my_circles() from public, anon;
grant execute on function public.my_circles() to authenticated;

drop policy if exists docs_teacher_select on public.docs;
drop policy if exists docs_teacher_insert on public.docs;
drop policy if exists docs_teacher_update on public.docs;
create policy docs_teacher_select on public.docs for select
  using (public.my_role() = 'teacher' and
         (coll = 'cfg' or (coll in ('students','records','audit') and circle_id = any(public.my_circles()))));
create policy docs_teacher_insert on public.docs for insert
  with check (public.my_role() = 'teacher' and coll in ('students','records','audit')
              and circle_id = any(public.my_circles()));
create policy docs_teacher_update on public.docs for update
  using (public.my_role() = 'teacher' and coll in ('students','records') and circle_id = any(public.my_circles()))
  with check (public.my_role() = 'teacher' and coll in ('students','records') and circle_id = any(public.my_circles()));
