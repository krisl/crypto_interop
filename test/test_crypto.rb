require 'minitest/autorun'
require 'crypto_interop'

class CryptoTest < Minitest::Test
  def test_Rfc2898DeriveBytes
    pass = 'password'
    salt = 'saltsalt'
    hurr = CryptoInterop::Rfc2898DeriveBytes.new(pass, salt)
    assert_equal "\xE9\xFE\xBF\xF5K\xFC\xE6h\xFD".b, hurr.get_bytes(9)
    assert_equal "\xE3\x01\xAC\xC8".b, hurr.get_bytes(4)
    assert_equal "Uc\xCC\x9D".b, hurr.get_bytes(4)
    assert_equal "\xC7\x1E\xF6\xF8\xD7\xAA\xEF\x06se\xBE\x0E^e\"\xEFa\xBA\xE1\xB0\v\xC1;\xCD\x05G<\xCC\rE\xFB\x04\v\xAD\xDF\xE9\x1A\xA6\xD6\xEF".b, hurr.get_bytes(40)
  end

  def test_rijndael
    pass = 'password'
    salt = 'saltsalt'
    pbkdf = CryptoInterop::Rfc2898DeriveBytes.new(pass, salt)
    aes = CryptoInterop::Rijndael.new_with_pbkdf(pbkdf)
    assert_equal "\xC6\xBFe\x8A1\x8B\xCD>\x80\xE6\x9A1c\x0F\x99j\xA8,\xDCy\xFE\x8B\xF9k\xE2\xEBNlOh\xE1\x8A".b, aes.encrypt('really secret stuff')
  end
end
