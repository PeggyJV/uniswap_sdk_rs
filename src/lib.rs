use std::ops::Rem;

use num_bigint::{BigInt,ToBigInt};
use num_traits::{One, Signed, Zero};


pub fn encode_sqrt_ratio_x96(amount1: BigInt, amount0: BigInt)->BigInt {

let numberator = amount1 << 192;

let ratio_x192:BigInt = numberator / amount0 ;

return ratio_x192.sqrt();
}


fn mulShift(val: BigInt, mulBy: &[u8])-> BigInt {
    let mulBy = BigInt::parse_bytes(mulBy,16 ).unwrap();
    return (val * mulBy) >> 128;
  }

pub fn getSqrtRatioAtTick(tick: BigInt)->BigInt {

    let MIN_TICK:BigInt = -887272.to_bigint().unwrap();

    let MAX_TICK:BigInt = -(MIN_TICK.clone());

    let MIN_SQRT_RATIO: BigInt = 4295128739i64.to_bigint().unwrap();

    let MAX_SQRT_RATIO: BigInt = BigInt::parse_bytes(b"1461446703485210103287273052203988822378723970342",10).unwrap();
    
    let MAX_UINT_256: BigInt = BigInt::parse_bytes(b"115792089237316195423570985008687907853269984665640564039457584007913129639935",10).unwrap();
    
    let Q32: BigInt = 2i32.to_bigint().unwrap().pow(32);


    assert!(tick >= MIN_TICK.clone() && tick <= MAX_TICK);
    let tick = tick.abs();
    let ratio = if tick.clone() & BigInt::one() !=BigInt::zero() {
        BigInt::parse_bytes(b"fffcb933bd6fad37aa2d162d1a594001", 16).unwrap() 
    } else{
        BigInt::parse_bytes(b"100000000000000000000000000000000", 16).unwrap()
    };
    let ratio = if (tick.clone() & BigInt::parse_bytes(b"2", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"fff97272373d413259a46990580e213a")}else{ratio};
    let ratio = if (tick.clone() & BigInt::parse_bytes(b"4", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"fff2e50f5f656932ef12357cf3c7fdcc")}else{ratio};
    let ratio = if (tick.clone() & BigInt::parse_bytes(b"8", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"ffe5caca7e10e4e61c3624eaa0941cd0")}else{ratio};
    let ratio = if (tick.clone() & BigInt::parse_bytes(b"10", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"ffcb9843d60f6159c9db58835c926644")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"20", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"ff973b41fa98c081472e6896dfb254c0")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"40", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"ff2ea16466c96a3843ec78b326b52861")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"80", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"fe5dee046a99a2a811c461f1969c3053")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"100", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"fcbe86c7900a88aedcffc83b479aa3a4")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"200", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"f987a7253ac413176f2b074cf7815e54")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"400", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"f3392b0822b70005940c7a398e4b70f3")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"800", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"e7159475a2c29b7443b29c7fa6e889d9")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"1000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"d097f3bdfd2022b8845ad8f792aa5825")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"2000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"a9f746462d870fdf8a65dc1f90e061e5")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"4000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"70d869a156d2a1b890bb3df62baf32f7")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"8000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"31be135f97d08fd981231505542fcfa6")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"10000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"9aa508b5b7a84e1c677de54f3e99bc9")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"20000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"5d6af8dedb81196699c329225ee604")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"40000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"2216e584f5fa1ea926041bedfe98")}else{ratio};
    let ratio =if (tick.clone() & BigInt::parse_bytes(b"80000", 16).unwrap()) != BigInt::zero() {mulShift(ratio, b"48a170391f7dc42444e8fa2")}else{ratio};

    let ratio =if tick.clone() > BigInt::zero() {MAX_UINT_256 / ratio}else{ ratio };

    let ratio =if ratio.clone().rem(Q32.clone()) > BigInt::zero()
     {
    ratio/Q32 + BigInt::one()

    }else{
        ratio/Q32
    };
    return ratio;
}

// pub fn getTickAtSqrtRatio()






#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{ToBigInt};
    #[test]
    fn encode_sqrt_ratio_x96_1() {
        let x = encode_sqrt_ratio_x96(100.to_bigint().unwrap(), 1.to_bigint().unwrap());
        assert_eq!(x, 792281625142643375935439503360i128.to_bigint().unwrap());
    }
    #[test]
    fn encode_sqrt_ratio_x96_2() {
        let x = encode_sqrt_ratio_x96(1.to_bigint().unwrap(), 100.to_bigint().unwrap());
        assert_eq!(x, 7922816251426433759354395033i128.to_bigint().unwrap());
    }
    #[test]
    fn encode_sqrt_ratio_x96_3() {
        let x = encode_sqrt_ratio_x96(111.to_bigint().unwrap(), 333.to_bigint().unwrap());
        assert_eq!(x, 45742400955009932534161870629i128.to_bigint().unwrap());
    }
    #[test]
    fn encode_sqrt_ratio_x96_4() {
        let x = encode_sqrt_ratio_x96(333.to_bigint().unwrap(), 111.to_bigint().unwrap());
        assert_eq!(x, 137227202865029797602485611888i128.to_bigint().unwrap());
    }
    #[test]
    fn getSqrtRatioAtTick_1() {
        let MIN_TICK:BigInt = -887272.to_bigint().unwrap();

        let MIN_SQRT_RATIO: BigInt = 4295128739i64.to_bigint().unwrap();

        let x = getSqrtRatioAtTick(MIN_SQRT_RATIO);
        assert_eq!(x, MIN_TICK);
    }

}
