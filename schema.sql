-- On Game: схема Supabase для первой версии
-- Запускай целиком в Supabase Dashboard -> SQL Editor.
-- После выполнения назначь роль moderator/admin только доверенным аккаунтам.
-- ВАЖНО: никогда не помещай service_role key в HTML.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (char_length(username) between 3 and 24),
  bio text not null default '' check (char_length(bio) <= 240),
  avatar_url text,
  role text not null default 'user' check (role in ('user','moderator','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.trophies (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  name text not null check (char_length(name) between 2 and 100),
  description text not null default '',
  rarity text not null default 'Обычный'
    check (rarity in ('Обычный','Редкий','Эпический','Легендарный','Уникальный')),
  icon text not null default '🏆',
  active boolean not null default true,
  sort_order integer not null default 100,
  created_at timestamptz not null default now()
);

create table if not exists public.submissions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  title text not null check (char_length(title) between 3 and 100),
  game text not null check (char_length(game) between 1 and 80),
  description text not null check (char_length(description) between 5 and 1500),
  evidence_url text not null check (char_length(evidence_url) <= 2000),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  moderator_id uuid references public.profiles(id),
  moderator_note text check (char_length(moderator_note) <= 500),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create table if not exists public.awards (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  trophy_id uuid not null references public.trophies(id),
  submission_id uuid not null unique references public.submissions(id),
  awarded_by uuid not null references public.profiles(id),
  moderator_note text check (char_length(moderator_note) <= 500),
  awarded_at timestamptz not null default now()
);

create index if not exists submissions_user_created_idx on public.submissions(user_id, created_at desc);
create index if not exists submissions_status_created_idx on public.submissions(status, created_at);
create index if not exists awards_user_date_idx on public.awards(user_id, awarded_at desc);

-- Создание профиля после регистрации Supabase Auth.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
declare
  desired_username text;
begin
  desired_username := coalesce(nullif(trim(new.raw_user_meta_data->>'username'), ''), 'Player_' || substr(new.id::text, 1, 8));
  insert into public.profiles(id, username)
  values (new.id, left(desired_username, 24))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Проверка роли на сервере. Не доверяет данным из браузера.
create or replace function public.is_moderator()
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('moderator','admin')
  );
$$;

-- Единственная точка принятия решения модератором.
create or replace function public.review_submission(
  p_submission_id uuid,
  p_status text,
  p_trophy_id uuid default null,
  p_moderator_note text default null
)
returns void language plpgsql security definer set search_path = public
as $$
declare
  s public.submissions%rowtype;
begin
  if auth.uid() is null or not public.is_moderator() then
    raise exception 'Только модератор может проверять заявки';
  end if;
  if p_status not in ('approved','rejected') then
    raise exception 'Недопустимый статус';
  end if;
  if p_moderator_note is not null and char_length(p_moderator_note) > 500 then
    raise exception 'Комментарий слишком длинный';
  end if;

  select * into s from public.submissions
  where id = p_submission_id for update;
  if not found then raise exception 'Заявка не найдена'; end if;
  if s.status <> 'pending' then raise exception 'Заявка уже рассмотрена'; end if;

  if p_status = 'approved' then
    if p_trophy_id is null then raise exception 'Выбери трофей'; end if;
    if not exists(select 1 from public.trophies where id = p_trophy_id and active = true) then
      raise exception 'Трофей не найден или отключён';
    end if;
    insert into public.awards(user_id, trophy_id, submission_id, awarded_by, moderator_note)
    values (s.user_id, p_trophy_id, s.id, auth.uid(), p_moderator_note);
  end if;

  update public.submissions
  set status = p_status, moderator_id = auth.uid(),
      moderator_note = p_moderator_note, reviewed_at = now()
  where id = s.id;
end;
$$;

alter table public.profiles enable row level security;
alter table public.trophies enable row level security;
alter table public.submissions enable row level security;
alter table public.awards enable row level security;

-- Публичные профили; менять можно только собственные безопасные поля.
drop policy if exists "profiles readable by everyone" on public.profiles;
create policy "profiles readable by everyone" on public.profiles for select using (true);
drop policy if exists "users update own profile" on public.profiles;
create policy "users update own profile" on public.profiles for update to authenticated
using (id = auth.uid()) with check (id = auth.uid());

-- Не даём обычному пользователю повысить себе роль через REST API.
create or replace function public.protect_profile_role()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if new.role is distinct from old.role and not exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  ) then
    raise exception 'Изменять роль может только администратор';
  end if;
  return new;
end;
$$;
drop trigger if exists protect_profile_role_trigger on public.profiles;
create trigger protect_profile_role_trigger
before update on public.profiles
for each row execute procedure public.protect_profile_role();

-- Каталог трофеев публичный, изменять каталог напрямую может только администратор через SQL.
drop policy if exists "active trophies readable" on public.trophies;
create policy "active trophies readable" on public.trophies for select using (active = true or public.is_moderator());

-- Пользователи создают заявки только от себя; видят свои, модераторы видят очередь.
drop policy if exists "read own submissions or moderation" on public.submissions;
create policy "read own submissions or moderation" on public.submissions for select to authenticated
using (user_id = auth.uid() or public.is_moderator());
drop policy if exists "create own pending submission" on public.submissions;
create policy "create own pending submission" on public.submissions for insert to authenticated
with check (user_id = auth.uid() and status = 'pending' and moderator_id is null and reviewed_at is null);
drop policy if exists "moderators update submissions" on public.submissions;
create policy "moderators update submissions" on public.submissions for update to authenticated
using (public.is_moderator()) with check (public.is_moderator());

-- Публичные выданные трофеи и дата; запись создаёт только защищённая RPC-функция.
drop policy if exists "awards public read" on public.awards;
create policy "awards public read" on public.awards for select using (true);

revoke all on function public.review_submission(uuid,text,uuid,text) from public;
grant execute on function public.review_submission(uuid,text,uuid,text) to authenticated;
grant execute on function public.is_moderator() to anon, authenticated;

-- Стартовый каталог. Можно изменить названия и описания.
insert into public.trophies(code,name,description,rarity,icon,sort_order) values
('GT-001','Первый шаг','За первое подтверждённое игровое достижение.','Обычный','🎮',1),
('GT-010','Охотник за ачивками','За коллекцию из десяти подтверждённых достижений.','Редкий','💎',10),
('GT-020','Мастер PvP','За подтверждённый выдающийся результат в PvP.','Эпический','⚔️',20),
('GT-099','Легенда','За исключительный игровой результат.','Легендарный','👑',99),
('GT-014','Исследователь','За открытие сложного секрета или скрытой локации.','Редкий','🧭',14),
('GT-027','Без единой ошибки','За прохождение сложного испытания без поражений.','Эпический','✨',27)
on conflict (code) do nothing;

-- После регистрации нужного аккаунта выполни отдельно:
-- update public.profiles set role = 'admin' where username = 'ТВОЙ_НИКНЕЙМ';
-- Не выдавай роль admin/moderator обычным пользователям.
