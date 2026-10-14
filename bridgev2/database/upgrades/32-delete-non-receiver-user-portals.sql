-- v32 (compatible with v9+): Delete user portals of non-receiver logins left behind by split portal migration
DELETE FROM user_portal
WHERE portal_receiver<>'' AND login_id<>portal_receiver AND EXISTS(
	SELECT 1 FROM kv_store
	WHERE kv_store.bridge_id=user_portal.bridge_id AND kv_store.key='split_portals_enabled' AND kv_store.value='true'
);
