create table users (
  `id` varchar(36) not null primary key, 
  `email` varchar(127) not null unique,
  `password` varchar(127) not null,
  `created_at` timestamp
);

create table labels (
  `id` varchar(36) not null primary key,
  `user_id` varchar(36) not null,
  `title` varchar(32) not null,
  `color` varchar(32) not null default "#FFFFFF",
  `created_at` timestamp,
  `updated_at` datetime on update current_timestamp
);

create table tasks (
  `id` varchar(36) not null primary key,
  `user_id` varchar(36) not null,
  `title` varchar(32) not null,
  `content` text,
  `created_at` timestamp,
  `updated_at` datetime on update current_timestamp
);

create table task_labels (
  `label_id` varchar(36) not null,
  `task_id` varchar(36) not null
);

alter table labels add foreign key (`user_id`) references users(`id`) on update cascade on delete cascade;
alter table tasks add foreign key (`user_id`) references users(`id`) on update cascade on delete cascade;
alter table task_labels add foreign key (`task_id`) references tasks(`id`) on update cascade on delete cascade;
alter table task_labels add foreign key (`label_id`) references labels(`id`) on update cascade on delete cascade;
