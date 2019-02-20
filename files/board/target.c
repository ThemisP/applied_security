/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h"

/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */

int  octetstr_rd(       uint8_t* r, int n_r ) {
  for(int i=0; i<n_r;i++){

  }
  return 0;
}

/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */

void octetstr_wr( const uint8_t* x, int n_x ) {
  for(int i=0; i<n_x;i++){

  }
  return;
}

/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  *
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes_init(                               const uint8_t* k, const uint8_t* r ) {
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  *
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* rc) {
  aes_enc_rnd_key(m, k);
  for(uint8_t i=1; i<10;i++){
    aes_enc_rnd_sub(m);
    aes_enc_rnd_row(m);
    aes_enc_rnd_mix(m);
    aes_enc_exp_step(k, rc);
    aes_enc_rnd_key(m, k);
    rc = xtime(rc);
  }
  aes_enc_rnd_sub(m);
  aes_enc_rnd_row(m);
  aes_enc_exp_step(k, rc);
  aes_enc_rnd_key(m, k);
  memcpy(c, m, sizeof(uint8_t)*16);
  return;
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART,
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART,
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  if( !scale_init( &SCALE_CONF ) ) {
    return -1;
  }

  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = { 0xA3, 0x37, 0x82, 0xF8, 0x52, 0xE3, 0x8E, 0x07, 0xDA, 0x97, 0x30, 0x10, 0x70, 0x3F, 0x6F, 0xEE }, r[ SIZEOF_RND ];

  while( true ) {
    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_KEY;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_RND;
                    octetstr_wr( &t, 1 );

        break;
      }
      case COMMAND_ENCRYPT : {
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

                          octetstr_wr( c, SIZEOF_BLK );

        break;
      }
      default : {
        break;
      }
    }
  }

  return 0;
}

void aes_enc( uint8_t* c, uint8_t* m, uint8_t* k ){
  uint8_t rc = 1;
  aes_enc_rnd_key(m, k);
  for(uint8_t i=1; i<10;i++){
    aes_enc_rnd_sub(m);
    aes_enc_rnd_row(m);
    aes_enc_rnd_mix(m);
    aes_enc_exp_step(k, rc);
    aes_enc_rnd_key(m, k);
    rc = xtime(rc);
  }
  aes_enc_rnd_sub(m);
  aes_enc_rnd_row(m);
  aes_enc_exp_step(k, rc);
  aes_enc_rnd_key(m, k);
  memcpy(c, m, sizeof(uint8_t)*16);
}

void aes_enc_rnd_mix( aes_gf28_t* s ){
  for(int i=0;i<4;i++){
    int a = 0+(i*4), b = 1+(i*4);
    int c = 2+(i*4), d = 3+(i*4);
    aes_gf28_t a1 = s[a];
    aes_gf28_t b1 = s[b];
    aes_gf28_t c1 = s[c];
    aes_gf28_t d1 = s[d];

    aes_gf28_t a2 = xtime(a1);
    aes_gf28_t b2 = xtime(b1);
    aes_gf28_t c2 = xtime(c1);
    aes_gf28_t d2 = xtime(d1);

    aes_gf28_t a3 = a1^a2;
    aes_gf28_t b3 = b1^b2;
    aes_gf28_t c3 = c1^c2;
    aes_gf28_t d3 = d1^d2;

    s[a] = a2^b3^c1^d1;
    s[b] = a1^b2^c3^d1;
    s[c] = a1^b1^c2^d3;
    s[d] = a3^b1^c1^d2;
  }
}

void aes_enc_rnd_row( aes_gf28_t* s ){
  aes_gf28_t a1 = s[1];
  aes_gf28_t b1 = s[5];
  aes_gf28_t c1 = s[9];
  aes_gf28_t d1 = s[13];

  s[13] = a1;
  s[1] = b1;
  s[5] = c1;
  s[9] = d1;

  a1 = s[2];
  b1 = s[6];
  c1 = s[10];
  d1 = s[14];

  s[10] = a1;
  s[14] = b1;
  s[2] = c1;
  s[6] = d1;

  a1 = s[3];
  b1 = s[7];
  c1 = s[11];
  d1 = s[15];

  s[7] = a1;
  s[11] = b1;
  s[15] = c1;
  s[3] = d1;
}

void aes_enc_rnd_sub( aes_gf28_t* s ){
  for(int i=0; i<16;i++){
    s[i] = sbox(s[i]);
  }
}

void aes_enc_rnd_key( aes_gf28_t* s, aes_gf28_t* rk ){
  for(int i=0;i<16;i++){
    s[i] = s[i]^rk[i];
  }
}

void aes_enc_exp_step( aes_gf28_t* rk, gf28_k rc ){
  aes_gf28_t r[16];
  r[  0 ] = rc ^ sbox( rk[ 13 ] ) ^ rk[  0 ];
  r[  1 ] =      sbox( rk[ 14 ] ) ^ rk[  1 ];
  r[  2 ] =      sbox( rk[ 15 ] ) ^ rk[  2 ];
  r[  3 ] =      sbox( rk[ 12 ] ) ^ rk[  3 ];

  r[  4 ] =                        r[  0 ]    ^ rk[  4 ];
  r[  5 ] =                        r[  1 ]    ^ rk[  5 ];
  r[  6 ] =                        r[  2 ]    ^ rk[  6 ];
  r[  7 ] =                        r[  3 ]    ^ rk[  7 ];

  r[  8 ] =                        r[  4 ]    ^ rk[  8 ];
  r[  9 ] =                        r[  5 ]    ^ rk[  9 ];
  r[ 10 ] =                        r[  6 ]    ^ rk[ 10 ];
  r[ 11 ] =                        r[  7 ]    ^ rk[ 11 ];

  r[ 12 ] =                        r[  8 ]    ^ rk[ 12 ];
  r[ 13 ] =                        r[  9 ]    ^ rk[ 13 ];
  r[ 14 ] =                        r[ 10 ]    ^ rk[ 14 ];
  r[ 15 ] =                        r[ 11 ]    ^ rk[ 15 ];
  memcpy(rk, r, sizeof(r));
}

aes_gf28_t sbox(aes_gf28_t a){
  return sboxlookup[a];
}

aes_gf28_t xtime(aes_gf28_t a){
  if(((a>>7) & 0x01) == 0x01){
    return (a<<1)^ 0x1B;
  } else {
    return (a<<1);
  }
}
