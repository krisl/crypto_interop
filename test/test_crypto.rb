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
end
