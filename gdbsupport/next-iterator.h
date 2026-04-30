/* A "next" iterator for GDB, the GNU debugger.
   Copyright (C) 2019-2026 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef GDBSUPPORT_NEXT_ITERATOR_H
#define GDBSUPPORT_NEXT_ITERATOR_H

#include "gdbsupport/iterator-range.h"

/* An iterator base class that defines pretty much everything except how to
   obtain the next element, given the current element.

   Increment is a functor that takes a T& and returns the next T* in the
   sequence.  It shall return nullptr when there are no more elements.  */

template<typename T, typename Incrementer>
struct base_next_iterator
{
  using self_type = base_next_iterator<T, Incrementer>;
  using value_type = T *;
  using reference = T *&;
  using pointer = T **;
  using iterator_category = std::forward_iterator_tag;
  using difference_type = int;

  explicit base_next_iterator (T *item)
    : m_item (item)
  {
  }

  /* Create a one-past-the-end iterator.  */
  base_next_iterator ()
    : m_item (nullptr)
  {
  }

  value_type operator* () const
  {
    return m_item;
  }

  bool operator== (const self_type &other) const
  {
    return m_item == other.m_item;
  }

  bool operator!= (const self_type &other) const
  {
    return m_item != other.m_item;
  }

  self_type &operator++ ()
  {
    gdb_assert (m_item != nullptr);
    this->m_item = Incrementer () (*m_item);
    return *this;
  }

private:
  T *m_item;
};

/* Iterator that follows the `next` field of a type.  */

template <typename T>
struct next_field_incrementer
{
  T *operator() (T &item) const noexcept
  {
    return item.next;
  }
};

template <typename T>
using next_iterator = base_next_iterator<T, next_field_incrementer<T>>;

template <typename T>
using next_range = iterator_range<next_iterator<T>>;

#endif /* GDBSUPPORT_NEXT_ITERATOR_H */
