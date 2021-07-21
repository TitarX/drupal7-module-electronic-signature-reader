<?php

function check_roles(array $access_roles): bool {
  global $user;

  foreach ($access_roles as $access_role) {
    if (in_array($access_role, $user->roles)) {
      return TRUE;
    }
  }

  return FALSE;
}
