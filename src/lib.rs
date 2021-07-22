use std::{cmp::Ordering, ops::{Mul, Rem}, ptr::read};

use num_bigint::{BigInt, ToBigInt};
use num_traits::{One, Signed, ToPrimitive, Zero};

pub fn encode_sqrt_ratio_x96(amount1: BigInt, amount0: BigInt) -> BigInt {
    let numberator = amount1 << 192;

    let ratio_x192: BigInt = numberator / amount0;

    return ratio_x192.sqrt();
}

fn mulShift(val: BigInt, mulBy: &[u8]) -> BigInt {
    let mulBy = BigInt::parse_bytes(mulBy, 16).unwrap();
    return (val * mulBy) >> 128;
}

pub fn getSqrtRatioAtTick(tick: BigInt) -> BigInt {
    let MIN_TICK: BigInt = -887272.to_bigint().unwrap();

    let MAX_TICK: BigInt = -(MIN_TICK.clone());

    let MAX_UINT_256: BigInt = BigInt::parse_bytes(
        b"115792089237316195423570985008687907853269984665640564039457584007913129639935",
        10,
    )
    .unwrap();

    let Q32: BigInt = 2i32.to_bigint().unwrap().pow(32);

    assert!(tick >= MIN_TICK.clone() && tick <= MAX_TICK);
    let absTick = tick.abs();
    let mut ratio = if absTick.clone() & BigInt::one() != BigInt::zero() {
        BigInt::parse_bytes(b"fffcb933bd6fad37aa2d162d1a594001", 16).unwrap()
    } else {
        BigInt::parse_bytes(b"100000000000000000000000000000000", 16).unwrap()
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"2", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"fff97272373d413259a46990580e213a")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"4", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"fff2e50f5f656932ef12357cf3c7fdcc")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"8", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"ffe5caca7e10e4e61c3624eaa0941cd0")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"10", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"ffcb9843d60f6159c9db58835c926644")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"20", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"ff973b41fa98c081472e6896dfb254c0")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"40", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"ff2ea16466c96a3843ec78b326b52861")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"80", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"fe5dee046a99a2a811c461f1969c3053")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"100", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"fcbe86c7900a88aedcffc83b479aa3a4")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"200", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"f987a7253ac413176f2b074cf7815e54")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"400", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"f3392b0822b70005940c7a398e4b70f3")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"800", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"e7159475a2c29b7443b29c7fa6e889d9")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"1000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"d097f3bdfd2022b8845ad8f792aa5825")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"2000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"a9f746462d870fdf8a65dc1f90e061e5")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"4000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"70d869a156d2a1b890bb3df62baf32f7")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"8000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"31be135f97d08fd981231505542fcfa6")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"10000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"9aa508b5b7a84e1c677de54f3e99bc9")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"20000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"5d6af8dedb81196699c329225ee604")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"40000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"2216e584f5fa1ea926041bedfe98")
    } else {
        ratio
    };
    ratio = if (absTick.clone() & BigInt::parse_bytes(b"80000", 16).unwrap()) != BigInt::zero() {
        mulShift(ratio, b"48a170391f7dc42444e8fa2")
    } else {
        ratio
    };

    ratio = if tick.clone() > BigInt::zero() {
        MAX_UINT_256 / ratio
    } else {
        ratio
    };

    ratio = if ratio.clone().rem(Q32.clone()) > BigInt::zero() {
        ratio / Q32 + BigInt::one()
    } else {
        ratio / Q32
    };
    return ratio;
}

pub fn getTickAtSqrtRatio(sqrtRatioX96: BigInt) -> i32 {
    let MIN_SQRT_RATIO: BigInt = 4295128739i64.to_bigint().unwrap();

    let MAX_SQRT_RATIO: BigInt =
        BigInt::parse_bytes(b"1461446703485210103287273052203988822378723970342", 10).unwrap();

    assert!(sqrtRatioX96 >= MIN_SQRT_RATIO && sqrtRatioX96 < MAX_SQRT_RATIO);

    let sqrtRatioX128: BigInt = sqrtRatioX96.clone() << 32;
    let msb = most_significant_bit(sqrtRatioX128.clone());

    let mut r = if msb >= 128.to_bigint().unwrap() {
        sqrtRatioX128.clone() >> (msb.to_i64().unwrap() - 127)
    } else {
        sqrtRatioX128 << (127 - msb.to_i64().unwrap())
    };

    let mut log_2 = (msb - 128.to_bigint().unwrap()) << 64;

    for i in 0..14 {
        r = (r.clone() * r) >> 127;
        let f: BigInt = r.clone() >> 128;
        log_2 = log_2 | (f.clone() <<(63 - i));
        r = r >> f.clone().to_i64().unwrap();
    }

    let loq_sqrt0001: BigInt =
        log_2 * BigInt::parse_bytes(b"255738958999603826347141", 10).unwrap();

    let tick_low: BigInt = (loq_sqrt0001.clone()
        - BigInt::parse_bytes(b"3402992956809132418596140100660247210", 10).unwrap())
        >> 128;
    let tick_low = tick_low.to_i32().unwrap();

    let tick_high: BigInt = (loq_sqrt0001.clone()
        + BigInt::parse_bytes(b"291339464771989622907027621153398088495", 10).unwrap())
        >> 128;
    let tick_high = tick_high.to_i32().unwrap();
    if tick_low == tick_high {
        return tick_low;
    } else if getSqrtRatioAtTick(tick_high.to_bigint().unwrap()) <= sqrtRatioX96 {
        return tick_high;
    } else {
        return tick_low;
    }
}

pub fn most_significant_bit(mut x: BigInt) -> BigInt {
    assert!(x.clone() >= BigInt::zero());
    let TWO: BigInt = 2.to_bigint().unwrap();
    let POWERS_OF_2: Vec<(u32, BigInt)> = [128u32, 64u32, 32u32, 16u32, 8u32, 4u32, 2u32, 1u32]
        .iter()
        .map(|x| (*x, TWO.pow(*x)))
        .collect();

    let MAX_UINT_256: BigInt = BigInt::parse_bytes(
        b"115792089237316195423570985008687907853269984665640564039457584007913129639935",
        10,
    )
    .unwrap();
    assert!(x.clone() < MAX_UINT_256);
    let mut msb = BigInt::zero();

    for (power, min) in POWERS_OF_2 {
        if x >= min {
            x >>= power;
            msb += power;
        }
    }

    return msb;
}
#[derive(Clone)]
pub struct Token{
    pub symbol: String,
    pub address: String,
}

impl Token {
    pub fn sorts_before(&self, other: &Token) -> bool {
         self.address.to_lowercase() < other.address.to_lowercase()
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Token) -> bool {
        self.symbol == other.symbol && self.address == other.address
    }
}

#[derive(Clone)]
pub struct Price{
    pub amount_0: BigInt,
    pub amount_1: BigInt,
    pub token_0: Token,
    pub token_1: Token,
}

impl PartialEq for Price {
    fn eq(&self, other: &Self) -> bool {
        self.amount_0 == other.amount_0 && self.amount_1 == other.amount_1 && self.token_0 == other.token_0 && self.token_1 == other.token_1
    }
}

impl Eq for Price {
}


impl std::cmp::PartialOrd for Price {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Price{
    fn cmp(&self, other: &Self) -> Ordering {
        (self.amount_0.clone() * other.amount_1.clone()).cmp(&(other.amount_0.clone() * self.amount_1.clone()))
    }
}


fn tickToPrice(base_token:Token,quote_token:Token,tick:BigInt) -> Price {

    let  Q96 = 2.to_bigint().unwrap().pow(96);
    let Q192 = Q96.pow(2);

    let sqrtRatioX96 = getSqrtRatioAtTick(tick);
    let ratioX192 = sqrtRatioX96.clone()*sqrtRatioX96;

    

    if base_token.sorts_before(&quote_token) {
        return Price{token_0:base_token,token_1:quote_token,amount_0:Q192,amount_1:ratioX192};
        } else{
            return Price{token_0:quote_token,token_1:base_token,amount_0:ratioX192,amount_1:Q192};
        }
}

fn priceToTick(price:Price)->i32{
    let sorted = price.token_0.sorts_before(&price.token_1.clone());
    let sqrtRatioX96 = if sorted {encode_sqrt_ratio_x96(price.amount_0.clone(), price.amount_1.clone())} else{encode_sqrt_ratio_x96(price.amount_1.clone(), price.amount_0.clone())};

    let tick = getTickAtSqrtRatio(sqrtRatioX96);
    let nextTickPrice = tickToPrice(price.token_0.clone(),price.token_1.clone(),tick+ BigInt::one());
    if sorted{
        if !(price < nextTickPrice) {
            return tick + 1;
        } else if !(price > nextTickPrice){
            return tick + 1;

        } else{
            return tick;
        }
    } else{
        return tick;

    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;
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
        let MIN_TICK = -887272i32;

        let MIN_SQRT_RATIO: BigInt = 4295128739i64.to_bigint().unwrap();

        let x = getSqrtRatioAtTick(MIN_TICK.to_bigint().unwrap());
        assert_eq!(x, MIN_SQRT_RATIO);
    }

    #[test]
    fn getSqrtRatioAtTick_2() {
        let MIN_TICK = -887272i32;
        let MAX_TICK = -MIN_TICK.clone();

        let MAX_SQRT_RATIO: BigInt =
        BigInt::parse_bytes(b"1461446703485210103287273052203988822378723970342", 10).unwrap();

        let x = getSqrtRatioAtTick(MAX_TICK.to_bigint().unwrap());
        assert_eq!(x, MAX_SQRT_RATIO);
    }

    #[test]
    fn getTickAtSqrtRatio_1() {
        let MIN_TICK = -887272i32;
        let MAX_TICK = -MIN_TICK.clone();

        let MIN_SQRT_RATIO: BigInt = 4295128739i64.to_bigint().unwrap();

        let x = getTickAtSqrtRatio(MIN_SQRT_RATIO);
        assert_eq!(x, MIN_TICK);
    }

    #[test]
    fn getTickAtSqrtRatio_2() {
        let MIN_TICK = -887272i32;
        let MAX_TICK = -MIN_TICK.clone();

        let MAX_SQRT_RATIO: BigInt =
        BigInt::parse_bytes(b"1461446703485210103287273052203988822378723970342", 10).unwrap();

        let x = getTickAtSqrtRatio(MAX_SQRT_RATIO-BigInt::one());
        assert_eq!(x, MAX_TICK -1);
    }

    #[test]
    fn test_most_significant_bits() {
        let TWO: BigInt = 2.to_bigint().unwrap();

        for i in 1u32..256u32 {
            let x = TWO.pow(i);
            assert_eq!(i.to_bigint().unwrap(), most_significant_bit(x))
        }

        for i in 2u32..256u32 {
            let x = TWO.pow(i) - BigInt::one();
            assert_eq!(
                i.to_bigint().unwrap() - BigInt::one(),
                most_significant_bit(x)
            )
        }
    }
}
