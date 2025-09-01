#include "hashtab.h"
#include <stdlib.h>
#include <string.h>

static void h_init(HTab *htab) {
    htab->tab = NULL;
    htab->mask = 0;
    htab->size = 0;
}

static void h_insert(HTab *htab, HNode *node) {
    size_t pos = node->hcode & htab->mask;
    HNode *next = htab->tab[pos];
    node->next = next;
    htab->tab[pos] = node;
    htab->size++;
}

static HNode **h_lookup(HTab *htab, HNode *key, bool (*eq)(HNode *, HNode *)) {
    if (!htab->tab) {
        return NULL;
    }

    size_t pos = key->hcode & htab->mask;
    HNode **from = &htab->tab[pos];
    while (*from) {
        if (eq(*from, key)) {
            return from;
        }
        from = &(*from)->next;
    }
    return NULL;
}

static void h_scan(HTab *htab, void (*f)(HNode *, void *), void *arg) {
    if (!htab->tab) {
        return;
    }
    for (size_t i = 0; i < htab->mask + 1; ++i) {
        HNode *node = htab->tab[i];
        while (node) {
            HNode *next = node->next;
            f(node, arg);
            node = next;
        }
    }
}

static void h_resize(HTab *htab) {
    size_t new_mask = htab->mask ? (htab->mask << 1) + 1 : 1;
    HNode **new_tab = (HNode **)calloc(new_mask + 1, sizeof(HNode *));
    size_t old_mask = htab->mask;
    HNode **old_tab = htab->tab;
    htab->tab = new_tab;
    htab->mask = new_mask;
    htab->size = 0;

    if (old_tab) {
        for (size_t i = 0; i < old_mask + 1; ++i) {
            HNode *node = old_tab[i];
            while (node) {
                HNode *next = node->next;
                h_insert(htab, node);
                node = next;
            }
        }
        free(old_tab);
    }
}

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
    HNode **from = h_lookup(&hmap->ht1, key, eq);
    if (from) {
        return *from;
    }
    from = h_lookup(&hmap->ht2, key, eq);
    if (from) {
        return *from;
    }
    return NULL;
}

void hm_insert(HMap *hmap, HNode *node) {
    if (!hmap->ht1.tab) {
        h_init(&hmap->ht1);
    }
    h_insert(&hmap->ht1, node);
    if (hmap->ht1.size > hmap->ht1.mask) {
        h_resize(&hmap->ht1);
    }
}

HNode *hm_pop(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
    HNode **from = h_lookup(&hmap->ht1, key, eq);
    if (from) {
        HNode *node = *from;
        *from = node->next;
        hmap->ht1.size--;
        return node;
    }
    from = h_lookup(&hmap->ht2, key, eq);
    if (from) {
        HNode *node = *from;
        *from = node->next;
        hmap->ht2.size--;
        return node;
    }
    return NULL;
}

size_t hm_size(HMap *hmap) {
    return hmap->ht1.size + hmap->ht2.size;
}

void hm_destroy(HMap *hmap) {
    if (hmap->ht1.tab) {
        free(hmap->ht1.tab);
    }
    if (hmap->ht2.tab) {
        free(hmap->ht2.tab);
    }
    h_init(&hmap->ht1);
    h_init(&hmap->ht2);
} 