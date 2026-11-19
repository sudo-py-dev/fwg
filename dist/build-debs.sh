#!/usr/bin/env bash
# Build native Debian binary packages from the locked Cargo workspace.
set -euo pipefail
umask 022
cd "$(dirname "${BASH_SOURCE[0]}")/.."
out="${1:-target/deb}"
# Debian sorts a tilde prerelease before the final release.
upstream=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml)
debian_prerelease="~"
version="${FWG_DEB_VERSION:-${upstream/-/$debian_prerelease}}"
dpkg --validate-version "$version"
arch=$(dpkg --print-architecture)
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# Keep the output path predictable even when CARGO_TARGET_DIR is set.
cargo build --locked --release --target-dir target -p fwg -p fwgd
mkdir -p "$stage/debian"
printf 'Source: fwg\n\nPackage: fwg\nArchitecture: any\n' > "$stage/debian/control"

for name in fwg fwgd; do
  pkg="$stage/debian/$name"
  doc="$pkg/usr/share/doc/$name"
  install -D -m 0755 "target/release/$name" "$pkg/usr/sbin/$name"
  strip --strip-unneeded "$pkg/usr/sbin/$name"
  install -D -m 0644 "dist/$name.service" "$pkg/usr/lib/systemd/system/$name.service"
  install -d -m 0755 "$pkg/DEBIAN" "$doc"
  {
    printf 'fwg is licensed under either the MIT or Apache License, Version 2.0.\n\n'
    cat LICENSE-MIT
    printf '\nOn Debian systems, the Apache License, Version 2.0, is available in\n/usr/share/common-licenses/Apache-2.0.\n'
  } > "$doc/copyright"

  depends=$(cd "$stage" && dpkg-shlibdeps -O "debian/$name/usr/sbin/$name")
  other=fwgd
  if [[ "$name" == fwg ]]; then
    description='firewall manager for nftables'
    install -d -m 0755 "$pkg/usr/share/fwg/apps"
    install -m 0644 apps/*.toml "$pkg/usr/share/fwg/apps/"
  else
    other=fwg
    description='log-based ban daemon for nftables'
    depends="$depends, fwg (>= $version)"
    install -d -m 0755 "$pkg/usr/share/fwg/filters"
    install -m 0644 filters/*.toml "$pkg/usr/share/fwg/filters/"
    install -d -m 0750 "$pkg/etc/fwg" "$pkg/etc/fwg/jails.d"
    install -m 0644 dist/jails.d/*.toml "$pkg/etc/fwg/jails.d/"
    for jail in dist/jails.d/*.toml; do
      printf '/etc/fwg/jails.d/%s\n' "${jail##*/}"
    done > "$pkg/DEBIAN/conffiles"
  fi
  for script in postinst prerm postrm; do
    sed -e "s/@PACKAGE@/$name/g" -e "s/@OTHER@/$other/g" "dist/deb/$script" > "$pkg/DEBIAN/$script"
    chmod 0755 "$pkg/DEBIAN/$script"
  done

  # Both supported distros ship the systemd helpers in Essential packages.
  cat > "$pkg/DEBIAN/control" <<CONTROL
Package: $name
Version: $version
Architecture: $arch
Section: net
Priority: optional
Maintainer: fwg contributors <sudo-py-dev@users.noreply.github.com>
Installed-Size: $(du -sk --exclude=DEBIAN "$pkg" | cut -f1)
Depends: nftables, systemd, ${depends#shlibs:Depends=}
Homepage: https://github.com/sudo-py-dev/fwg
Description: $description
 fwg (fwguard) manages firewall rules and log-based bans on Linux
 using nftables. See the project README for usage and configuration.
CONTROL
  (cd "$pkg" && find usr -type f -print0 | sort -z | xargs -0 -r md5sum) > "$pkg/DEBIAN/md5sums"
  # Use the same archive format on Ubuntu and Debian.
  dpkg-deb -Zxz --root-owner-group --build "$pkg" "$out"
done
