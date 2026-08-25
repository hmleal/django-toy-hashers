# Django Toy Hashers

Three deliberately insecure password hashers for Django, created for learning
and demonstrations:

- `ROT13PasswordHasher`
- `MD5PasswordHasher`
- `PlainTextPasswordHasher`

The goal is to make it easier to see what a password hasher does inside Django:
it encodes a password, stores the result, and later verifies a password against
that stored value.

## Important warning

These hashers are **not suitable for real applications**. ROT13 and plaintext
store reversible or directly readable passwords, and MD5 is not appropriate for
password storage. Use Django's default `PBKDF2PasswordHasher`, or another modern
password hashing algorithm, for production systems.

## Installation

From a local checkout:

```bash
uv add --editable ../django-toy-hashers
```

Or install the package with your preferred Python package manager after it has
been published.

## Configuration

Add the hashers to your Django settings. The first hasher in the list is used
when Django creates new passwords.

```python
PASSWORD_HASHERS = [
	"django_toy_hashers.hashers.ROT13PasswordHasher",
	"django_toy_hashers.hashers.MD5PasswordHasher",
	"django_toy_hashers.hashers.PlainTextPasswordHasher",
	"django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
```

For a demonstration, Django's normal password APIs can then be used:

```python
from django.contrib.auth.hashers import check_password, make_password

encoded = make_password("correct horse", hasher="rot13")
print(encoded)
print(check_password("correct horse", encoded))
```

The `hasher` argument accepts the algorithm name defined by each class:
`rot13`, `md5_custom`, or `plain_text`.

## Encoded formats

The examples use Django's usual `$`-separated encoded-password format:

```text
rot13$salt$rot13(salt + password)
md5_custom$10$salt$md5(md5(...md5(salt + password)))
plain_text$salt$password
```

The MD5 implementation repeats the digest ten times. That does not make MD5 a
safe password hashing algorithm; it is included only to illustrate the basic
shape of an iterative hasher.

## License

BSD 3-Clause
