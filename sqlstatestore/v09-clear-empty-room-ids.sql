-- v9 (compatible with v3+): Clear invalid rows
DELETE FROM mx_room_state WHERE room_id='';
DELETE FROM mx_user_profile WHERE room_id='' OR user_id='';
