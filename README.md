# Keepass

 <a href="https://travis-ci.org/lipanski/keepass"><img src="https://travis-ci.org/lipanski/keepass.svg?branch=master"></a>

A Keepass KDBX v2/v3 parser for Crystal.

## Requirements

This library requires **libsodium**. On Ubuntu 17.04 you can install it via `sudo apt install libsodium-dev`. For other distros, please check [the libsodium docs](https://download.libsodium.org/doc/).

## Install

Add the following lines to your `shard.yml`:

```yaml
dependencies:
  keepass:
    github: lipanski/keepass
```

...and run `crystal deps` or `shards install`.

## Usage

When the file is encrypted with a password:

```crystal
require "keepass"

database = Keepass.parse!("/path/to/keepass.kdbx", "password")
```

When the file is encrypted with a password and a key file:

```crystal
require "keepass"

database = Keepass.parse!("/path/to/keepass.kdbx", "password", "/path/to/keyfile")
```

### The Keepass::Database object

Read the version:

```crystal
database.version #=> String
```

Show the groups:

```crystal
database.groups #=> Array(Keepass::Group)
```

### The Keepass::Group object

Show the name:

```crystal
group.name #=> String
```

Show the ID:

```crystal
group.uuid #=> String
```

Show the entries directly under this group:

```crystal
group.entries #=> Array(Keepass::Entry)
```

Show all entries (including entries contained by sub-groups):

```crystal
group.all_entries #=> Array(Keepass::Entry)
```

Show sub-groups:

```crystal
group.groups #=> Array(Keepas::Group)
```

Show the parent group (if any):

```crystal
group.parent #=> Group?
```

### The Keepass::Entry object

Show the title:

```crystal
entry.title #=> String?
```

Show the ID:

```crystal
entry.uuid #=> String
```

Show the user name:

```crystal
entry.user_name #=> String?
```

Show the password:

```crystal
entry.password #=> String?
```

Show the notes:

```crystal
entry.notes #=> String?
```

Show some helpful timestamps:

```crystal
entry.created_at #=> Time?
entry.updated_at #=> Time?
entry.last_accessed_at #=> Time?
```

Show the usage count (if available):

```crystal
entry.usage_count #=> Int32?
```

### Errors

Check the [src/keepass/error.cr](https://github.com/lipanski/keepass/blob/master/src/keepass/error.cr) file for a list of the errors that will be raised.

## TODO

- [x] Accept key files.
- [ ] Write KDBX files.
- [ ] Parse KDB.
- [ ] Parse KDBX4.

Pull requests are welcome.

## Resources

- <https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45>
- <https://gist.github.com/msmuenchen/9318327>
- <https://github.com/mjwhitta/rubeepass>
- <https://github.com/Stoom/KeePass/wiki/KDBX-v2-File-Format>
- <https://github.com/lgg/awesome-keepass#docs-and-articles>
- <http://sketchingdev.co.uk/blog/why-you-cant-recover-your-keepass-password.html>
