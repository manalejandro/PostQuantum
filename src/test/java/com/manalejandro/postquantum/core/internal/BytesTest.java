/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BytesTest {

    @Test
    void concatenatesArrays() {
        assertThat(Bytes.concat(new byte[]{1, 2}, new byte[0], new byte[]{3}))
                .containsExactly(1, 2, 3);
        assertThat(Bytes.concat()).isEmpty();
    }

    @Test
    void producesAnAllBitsSetMaskOnlyForEqualArrays() {
        assertThat(Bytes.constantTimeMask(new byte[]{1, 2, 3}, new byte[]{1, 2, 3})).isEqualTo(-1);
        assertThat(Bytes.constantTimeMask(new byte[]{1, 2, 3}, new byte[]{1, 2, 4})).isZero();
        assertThat(Bytes.constantTimeMask(new byte[]{1, 2}, new byte[]{1, 2, 3})).isZero();
        assertThat(Bytes.constantTimeMask(new byte[0], new byte[0])).isEqualTo(-1);
        assertThat(Bytes.constantTimeMask(new byte[]{0, 0}, new byte[]{0, 0})).isEqualTo(-1);
    }

    @Test
    void selectsWithoutBranching() {
        byte[] left = {1, 2, 3};
        byte[] right = {4, 5, 6};

        assertThat(Bytes.constantTimeSelect(-1, left, right)).containsExactly(1, 2, 3);
        assertThat(Bytes.constantTimeSelect(0, left, right)).containsExactly(4, 5, 6);
        assertThatThrownBy(() -> Bytes.constantTimeSelect(-1, left, new byte[2]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
