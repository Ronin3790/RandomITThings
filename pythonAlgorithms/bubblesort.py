def bubbleSort(list):
  lastElementIndex = len(list) - 1                  # put last element of list in a variable
  for passNo in range(lastElementIndex,0, -1):      # loop over list and count number of passes
      for i in range(passNo):                       # loop over list to single out element and next element
          if list[i] > list[i+1]:                   # comparing each number with it's adjacent number
              list[i],list[i+1] = list[i+1],list[i] # variable swapping to adjust the number's position if needed.
      return list

list = [25, 21, 22, 24, 23, 27, 26]
print(bubbleSort(list))

    
