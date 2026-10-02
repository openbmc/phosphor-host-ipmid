# phosphor-host-ipmid

## Compile ipmid with default options

```ascii
meson builddir
ninja -C builddir
```

## Compile ipmid with yocto defaults

```ascii
meson builddir -Dbuildtype=minsize -Db_lto=true -Dtests=disabled
ninja -C builddir
```

If any of the dependencies are not found on the host system during
configuration, meson automatically gets them via its wrap dependencies mentioned
in `ipmid/subprojects`.

## Enable/Disable meson wrap feature

```ascii
meson builddir -Dwrap_mode=nofallback
ninja -C builddir
```

## Enable debug traces

```ascii
meson builddir -Dbuildtype=debug
ninja -C builddir
```

## Experimental self-test bypass

For platforms whose BIOS delays host boot on Get Self Test Results, enable:

```sh
meson setup builddir -Dexperimental-bypass-self-test=enabled
```

The command (Application NetFn `0x06`, command `0x04`) then returns completion
code `0x00` and data `55 00` immediately. This intentionally masks self-test
failures to avoid delaying or blocking host boot.

## Generate test coverage report

```ascii
meson builddir -Db_coverage=true -Dtests=enabled
ninja -C builddir test
ninja -C builddir coverage
```
