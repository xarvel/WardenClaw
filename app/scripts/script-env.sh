# SPDX-License-Identifier: GPL-3.0-or-later
# Sourced by scripts/eas_*.sh from app/. Reads only the script settings WARDENCLAW_* (APK folder,
# token file) from app/.env and app/.env.local. EXPO_PUBLIC_* stay out of the environment: they
# belong to the bundle, and a build for distribution must not see personal values
# (scripts/check-build-env.mjs).
for _wc_env in .env .env.local; do
  [ -f "$_wc_env" ] || continue
  while IFS='=' read -r _wc_k _wc_v; do
    _wc_v="${_wc_v%\"}"; _wc_v="${_wc_v#\"}"; _wc_v="${_wc_v%\'}"; _wc_v="${_wc_v#\'}"
    [ -n "$_wc_v" ] && export "$_wc_k=$_wc_v"
  done < <(grep -E '^WARDENCLAW_[A-Z0-9_]+=' "$_wc_env")
done
unset _wc_env _wc_k _wc_v
